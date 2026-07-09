use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// ALPN protocol identifier for Astralane TPU.
const ALPN_ASTRALANE_TPU: &[u8] = b"astralane-tpu";

/// Maximum Solana transaction size.
pub const MAX_TRANSACTION_SIZE: usize = 1232;

/// QUIC application error codes returned by the server.
pub mod error_code {
    pub const OK: u32 = 0;
    pub const UNKNOWN_API_KEY: u32 = 1;
    pub const CONNECTION_LIMIT: u32 = 2;

    pub fn describe(code: u32) -> &'static str {
        match code {
            OK => "OK",
            UNKNOWN_API_KEY => "Unknown API key",
            CONNECTION_LIMIT => "Connection limit exceeded",
            _ => "Unknown error",
        }
    }
}

/// A QUIC client for sending transactions to Astralane's TPU endpoint.
///
/// # Example
///
/// ```no_run
/// use astralane_quic_client::AstralaneQuicClient;
///
/// # async fn example() -> anyhow::Result<()> {
/// let client = AstralaneQuicClient::connect("fra.astralane.io:9000", "your-api-key-uuid").await?;
/// let tx_bytes: Vec<u8> = vec![]; // your bincode-serialized VersionedTransaction
/// client.send_transaction(&tx_bytes).await?;
/// # Ok(())
/// # }
/// ```
/// Maximum number of client-level reconnect attempts for recoverable errors
/// (UNKNOWN_API_KEY, CONNECTION_LIMIT) before giving up.
const MAX_RECONNECT_ATTEMPTS: u32 = 3;

/// Delay before each reconnect attempt for recoverable errors.
const RECONNECT_DELAY: Duration = Duration::from_secs(30);

/// Delay after reconnecting to verify the server accepted the connection
/// (server's post-handshake close frame may be in flight).
const RECONNECT_VERIFY_DELAY: Duration = Duration::from_millis(500);

pub struct AstralaneQuicClient {
    endpoint: Endpoint,
    /// Live connection, read lock-free on the send hot path via `load_full()`.
    connection: ArcSwap<Connection>,
    /// Serializes reconnect attempts only, so at most one reconnect (and its
    /// delay) runs at a time. Healthy sends never touch this lock.
    reconnect_lock: Mutex<()>,
    /// Serializes publishing a replacement connection with close(), without
    /// holding the reconnect lock across the 30s reconnect delay.
    publish_lock: StdMutex<()>,
    server_addr: SocketAddr,
    /// Client-level counter for reconnect attempts on error codes 1/2.
    /// Shared across all `send_transaction` calls. Resets on verified success.
    reconnect_attempts: AtomicU32,
    /// Set once `close()`/`Drop` runs. Coordinates with in-flight reconnects so
    /// a reconnect can't resurrect a live connection after the client is closed.
    closed: AtomicBool,
}

impl AstralaneQuicClient {
    /// Connect to an Astralane QUIC server.
    ///
    /// Generates a self-signed TLS certificate with the API key as the Common Name (CN).
    /// The server uses this CN to authenticate the client.
    ///
    /// # Arguments
    /// * `server_addr` - Server address in "host:port" format (e.g., "fra.astralane.io:9000")
    /// * `api_key` - Your API key UUID
    pub async fn connect(server_addr: &str, api_key: &str) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let addr = SocketAddr::from_str(server_addr)
            .or_else(|_| {
                // Try resolving as hostname:port
                use std::net::ToSocketAddrs;
                server_addr
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .ok_or_else(|| anyhow::anyhow!("Cannot resolve address: {}", server_addr))
            })
            .context("Invalid server address")?;

        info!(
            "[CLIENT] Building TLS config with api_key as CN: {}",
            api_key
        );
        let client_config = Self::build_client_config(api_key)?;

        let mut endpoint =
            Endpoint::client("0.0.0.0:0".parse()?).context("Failed to create QUIC endpoint")?;
        endpoint.set_default_client_config(client_config);

        info!("[CLIENT] Connecting to {} ...", addr);
        let connection = endpoint
            .connect(addr, "astralane")?
            .await
            .context("Failed to connect to Astralane QUIC server")?;

        info!(
            "[CLIENT] Connected to Astralane QUIC server at {} (api_key: {})",
            addr, api_key
        );

        Ok(Self {
            endpoint,
            connection: ArcSwap::from_pointee(connection),
            reconnect_lock: Mutex::new(()),
            publish_lock: StdMutex::new(()),
            server_addr: addr,
            reconnect_attempts: AtomicU32::new(0),
            closed: AtomicBool::new(false),
        })
    }

    /// Send a single bincode-serialized `VersionedTransaction`.
    ///
    /// This is fire-and-forget: returns `Ok(())` when the bytes are written to the stream.
    /// There is no server response. Automatically reconnects if the connection is dead.
    ///
    /// # Arguments
    /// * `transaction_bytes` - Bincode-serialized `VersionedTransaction` (max 1232 bytes)
    pub async fn send_transaction(&self, transaction_bytes: &[u8]) -> Result<()> {
        if transaction_bytes.len() > MAX_TRANSACTION_SIZE {
            anyhow::bail!(
                "Transaction too large: {} bytes (max {})",
                transaction_bytes.len(),
                MAX_TRANSACTION_SIZE
            );
        }
        self.ensure_open()?;

        // Read the live connection lock-free. Only if it is dead do we take the
        // reconnect path, which serializes on `reconnect_lock` (never on sends).
        let conn = self.connection.load_full();
        let conn = if conn.close_reason().is_some() {
            self.ensure_connection().await?
        } else {
            conn
        };

        info!(
            "[CLIENT] Opening uni stream to send {} bytes",
            transaction_bytes.len()
        );
        let mut send_stream = conn
            .open_uni()
            .await
            .context("Failed to open unidirectional stream")?;

        send_stream
            .write_all(transaction_bytes)
            .await
            .context("Failed to write transaction data")?;

        send_stream.finish().context("Failed to finish stream")?;
        info!(
            "[CLIENT] Transaction sent ({} bytes)",
            transaction_bytes.len()
        );

        Ok(())
    }

    /// Re-establish the connection after observing it is dead, returning a live
    /// `Arc<Connection>`.
    ///
    /// Serializes on `reconnect_lock` so only one reconnect (and its delay)
    /// runs at a time; concurrent sends that all observe the same dead
    /// connection collapse into a single reconnect. The `RECONNECT_DELAY` sleep
    /// runs while holding this lock — not a lock on the connection itself — so
    /// healthy sends and health-checks are never blocked by it.
    async fn ensure_connection(&self) -> Result<Arc<Connection>> {
        let _guard = self.reconnect_lock.lock().await;

        self.ensure_open()?;

        // Re-read under the lock: another task may have already reconnected, or
        // the connection may have since closed with a *different* reason. Base
        // the classification on the current connection's own close reason.
        let current = self.connection.load_full();
        let reason = match current.close_reason() {
            Some(reason) => reason,
            None => return Ok(current),
        };

        // Check if this is a recoverable application error
        let recoverable_code = if let quinn::ConnectionError::ApplicationClosed(ref info) = reason {
            let code = info.error_code.into_inner();
            if code == error_code::UNKNOWN_API_KEY as u64
                || code == error_code::CONNECTION_LIMIT as u64
            {
                Some(code)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(code) = recoverable_code {
            // Client-level retry for error codes 1/2.
            // Counter is only incremented on confirmed server rejection,
            // not on network failures during reconnect.
            let attempts = self.reconnect_attempts.load(Ordering::Relaxed);
            if attempts >= MAX_RECONNECT_ATTEMPTS {
                anyhow::bail!(
                    "Server closed connection: {} (code {}). All {} reconnect attempts exhausted.",
                    error_code::describe(code as u32),
                    code,
                    MAX_RECONNECT_ATTEMPTS
                );
            }
            warn!(
                "[CLIENT] Server closed connection: {} (code {}), reconnect attempt {}/{}  in {}s...",
                error_code::describe(code as u32),
                code,
                attempts + 1,
                MAX_RECONNECT_ATTEMPTS,
                RECONNECT_DELAY.as_secs()
            );
            tokio::time::sleep(RECONNECT_DELAY).await;
            self.ensure_open()?;
            let new_conn = Arc::new(
                self.endpoint
                    .connect(self.server_addr, "astralane")?
                    .await
                    .context("Failed to reconnect to Astralane QUIC server")?,
            );
            self.close_if_closed(&new_conn)?;

            // Wait for the server's post-handshake close frame before publishing.
            // We deliberately do NOT store `new_conn` yet: the old connection is
            // still dead, so any concurrent send stays parked in
            // `ensure_connection` behind `reconnect_lock` and can't write to this
            // unverified connection during the verification window.
            tokio::time::sleep(RECONNECT_VERIFY_DELAY).await;

            // Publish the verified outcome. Storing the (now terminal) connection
            // in both cases means a later send classifies/retries from *this*
            // connection's close reason rather than the previous (stale) one.
            let close_reason = self.publish_connection(new_conn)?;

            if close_reason.is_some() {
                // Server rejected again — increment counter
                let attempt = self.reconnect_attempts.fetch_add(1, Ordering::Relaxed) + 1;
                anyhow::bail!(
                    "Server closed connection again after reconnect attempt {}/{}:  {} (code {})",
                    attempt,
                    MAX_RECONNECT_ATTEMPTS,
                    error_code::describe(code as u32),
                    code
                );
            }

            // Reconnect verified — reset counter
            self.reconnect_attempts.store(0, Ordering::Relaxed);
            info!(
                "[CLIENT] Reconnected to {} (attempt {}/{}, verified alive)",
                self.server_addr,
                attempts + 1,
                MAX_RECONNECT_ATTEMPTS
            );
        } else {
            // Error code 0 or non-ApplicationClosed: reconnect immediately
            warn!(
                "[CLIENT] Connection dead, reconnecting to {} ...",
                self.server_addr
            );
            self.ensure_open()?;
            let new_conn = Arc::new(
                self.endpoint
                    .connect(self.server_addr, "astralane")?
                    .await
                    .context("Failed to reconnect to Astralane QUIC server")?,
            );
            self.publish_connection(new_conn)?;
            info!("[CLIENT] Reconnected to {}", self.server_addr);
        }

        Ok(self.connection.load_full())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            anyhow::bail!("Client is closed");
        }
        Ok(())
    }

    fn close_if_closed(&self, conn: &Connection) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            conn.close(error_code::OK.into(), b"client closing");
            anyhow::bail!("Client is closed");
        }
        Ok(())
    }

    fn publish_connection(
        &self,
        new_conn: Arc<Connection>,
    ) -> Result<Option<quinn::ConnectionError>> {
        let _guard = self
            .publish_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if self.closed.load(Ordering::SeqCst) {
            new_conn.close(error_code::OK.into(), b"client closing");
            anyhow::bail!("Client is closed");
        }

        let close_reason = new_conn.close_reason();
        self.connection.store(new_conn.clone());
        Ok(close_reason)
    }

    /// Reconnect to the server if the connection was closed.
    ///
    /// Note: `send_transaction` automatically reconnects, so you typically
    /// don't need to call this manually.
    pub async fn reconnect(&self) -> Result<()> {
        let _guard = self.reconnect_lock.lock().await;
        self.ensure_open()?;
        // Another task may have already reconnected while we waited for the lock.
        if self.connection.load().close_reason().is_some() {
            info!(
                "[CLIENT] Reconnecting to Astralane QUIC server at {}",
                self.server_addr
            );
            let new_conn = Arc::new(
                self.endpoint
                    .connect(self.server_addr, "astralane")?
                    .await
                    .context("Failed to reconnect to Astralane QUIC server")?,
            );
            self.publish_connection(new_conn)?;
            self.reconnect_attempts.store(0, Ordering::Relaxed);
            info!("[CLIENT] Reconnected to {}", self.server_addr);
        }
        Ok(())
    }

    /// Check if the connection is still alive.
    pub async fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::SeqCst) && self.connection.load().close_reason().is_none()
    }

    /// Close the connection gracefully.
    pub async fn close(&self) {
        let _guard = self
            .publish_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Set the flag while holding publish_lock so reconnect paths cannot
        // publish a replacement connection after close() has completed.
        self.closed.store(true, Ordering::SeqCst);
        self.connection
            .load()
            .close(error_code::OK.into(), b"client closing");
    }

    /// Build a quinn ClientConfig with a self-signed cert where CN = api_key.
    fn build_client_config(api_key: &str) -> Result<ClientConfig> {
        // Generate a self-signed certificate with the API key as CN
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut cert_params = CertificateParams::new(vec![])?;
        cert_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String(api_key.to_string()),
        );
        let cert = cert_params.self_signed(&key_pair)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        // Build rustls client config that skips server cert verification (server uses self-signed)
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_client_auth_cert(vec![cert_der], key_der)
            .context("Failed to set client certificate")?;

        crypto.alpn_protocols = vec![ALPN_ASTRALANE_TPU.to_vec()];

        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(25)));

        let mut client_config =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }
}

impl Drop for AstralaneQuicClient {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        // load() needs only &self and takes no lock — fine in Drop.
        self.connection
            .load()
            .close(error_code::OK.into(), b"client closing");
    }
}

/// Skip server certificate verification.
/// This is necessary because the Astralane server may use a self-signed certificate.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
