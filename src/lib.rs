use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// ALPN protocol identifier for Astralane TPU.
const ALPN_ASTRALANE_TPU: &[u8] = b"astralane-tpu";

/// Maximum wire size for legacy and v0 Solana transactions.
pub const MAX_LEGACY_TRANSACTION_SIZE: usize = 1232;

/// Backward-compatible alias for the legacy/v0 transaction limit.
pub const MAX_TRANSACTION_SIZE: usize = MAX_LEGACY_TRANSACTION_SIZE;

/// Maximum wire size for Solana v1 transactions.
pub const MAX_V1_TRANSACTION_SIZE: usize = 4096;

// SIMD-0385: v1 transactions start with the version byte and carry signatures at the end.
const V1_TRANSACTION_PREFIX: u8 = 0x81;

/// Return the protocol size limit for an encoded transaction payload.
#[must_use]
pub fn transaction_size_limit(transaction_bytes: &[u8]) -> usize {
    if transaction_bytes.first() == Some(&V1_TRANSACTION_PREFIX) {
        MAX_V1_TRANSACTION_SIZE
    } else {
        MAX_LEGACY_TRANSACTION_SIZE
    }
}

fn validate_transaction_size(transaction_bytes: &[u8]) -> Result<()> {
    if transaction_bytes.is_empty() {
        anyhow::bail!("Transaction payload is empty");
    }

    let max_size = transaction_size_limit(transaction_bytes);
    if transaction_bytes.len() > max_size {
        anyhow::bail!(
            "Transaction too large: {} bytes (max {} for {})",
            transaction_bytes.len(),
            max_size,
            if max_size == MAX_V1_TRANSACTION_SIZE {
                "v1"
            } else {
                "legacy/v0"
            }
        );
    }

    Ok(())
}

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
/// let tx_bytes: Vec<u8> = vec![]; // your Solana wire-encoded VersionedTransaction
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
    connection: Mutex<Connection>,
    server_addr: SocketAddr,
    /// Client-level counter for reconnect attempts on error codes 1/2.
    /// Shared across all `send_transaction` calls. Resets on verified success.
    reconnect_attempts: AtomicU32,
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
            connection: Mutex::new(connection),
            server_addr: addr,
            reconnect_attempts: AtomicU32::new(0),
        })
    }

    /// Send a single wire-encoded `VersionedTransaction`.
    ///
    /// This is fire-and-forget: returns `Ok(())` when the bytes are written to the stream.
    /// There is no server response. Automatically reconnects if the connection is dead.
    ///
    /// # Arguments
    /// * `transaction_bytes` - Solana wire bytes (1,232 bytes for legacy/v0; 4,096 for v1)
    pub async fn send_transaction(&self, transaction_bytes: &[u8]) -> Result<()> {
        validate_transaction_size(transaction_bytes)?;

        // Get the current connection, reconnecting if dead
        let conn = {
            let mut guard = self.connection.lock().await;
            if let Some(reason) = guard.close_reason() {
                // Check if this is a recoverable application error
                let recoverable_code =
                    if let quinn::ConnectionError::ApplicationClosed(ref info) = reason {
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
                    *guard = self
                        .endpoint
                        .connect(self.server_addr, "astralane")?
                        .await
                        .context("Failed to reconnect to Astralane QUIC server")?;

                    // Wait briefly for server's post-handshake close frame to arrive
                    tokio::time::sleep(RECONNECT_VERIFY_DELAY).await;
                    if guard.close_reason().is_some() {
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
                    *guard = self
                        .endpoint
                        .connect(self.server_addr, "astralane")?
                        .await
                        .context("Failed to reconnect to Astralane QUIC server")?;
                    info!("[CLIENT] Reconnected to {}", self.server_addr);
                }
            }
            guard.clone()
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

    /// Reconnect to the server if the connection was closed.
    ///
    /// Note: `send_transaction` automatically reconnects, so you typically
    /// don't need to call this manually.
    pub async fn reconnect(&self) -> Result<()> {
        let mut guard = self.connection.lock().await;
        if guard.close_reason().is_some() {
            info!(
                "[CLIENT] Reconnecting to Astralane QUIC server at {}",
                self.server_addr
            );
            *guard = self
                .endpoint
                .connect(self.server_addr, "astralane")?
                .await
                .context("Failed to reconnect to Astralane QUIC server")?;
            self.reconnect_attempts.store(0, Ordering::Relaxed);
            info!("[CLIENT] Reconnected to {}", self.server_addr);
        }
        Ok(())
    }

    /// Check if the connection is still alive.
    pub async fn is_connected(&self) -> bool {
        self.connection.lock().await.close_reason().is_none()
    }

    /// Close the connection gracefully.
    pub async fn close(&self) {
        self.connection
            .lock()
            .await
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
        // get_mut() avoids async lock — safe in Drop since we have &mut self
        self.connection
            .get_mut()
            .close(error_code::OK.into(), b"client closing");
    }
}

#[cfg(test)]
mod transaction_size_tests {
    use super::*;

    #[test]
    fn legacy_and_v0_keep_the_packet_data_limit() {
        let mut at_limit = vec![0u8; MAX_LEGACY_TRANSACTION_SIZE];
        at_limit[0] = 1; // compact signature count; v0 also starts with signatures
        assert_eq!(
            transaction_size_limit(&at_limit),
            MAX_LEGACY_TRANSACTION_SIZE
        );
        assert!(validate_transaction_size(&at_limit).is_ok());

        let mut over_limit = vec![0u8; MAX_LEGACY_TRANSACTION_SIZE + 1];
        over_limit[0] = 1;
        assert!(validate_transaction_size(&over_limit).is_err());
    }

    #[test]
    fn v1_accepts_the_larger_protocol_boundary() {
        for size in [MAX_LEGACY_TRANSACTION_SIZE + 1, MAX_V1_TRANSACTION_SIZE] {
            let mut transaction = vec![0u8; size];
            transaction[0] = V1_TRANSACTION_PREFIX;
            assert_eq!(
                transaction_size_limit(&transaction),
                MAX_V1_TRANSACTION_SIZE
            );
            assert!(validate_transaction_size(&transaction).is_ok());
        }

        let mut over_limit = vec![0u8; MAX_V1_TRANSACTION_SIZE + 1];
        over_limit[0] = V1_TRANSACTION_PREFIX;
        assert!(validate_transaction_size(&over_limit).is_err());
    }

    #[test]
    fn rejects_empty_payloads() {
        assert!(validate_transaction_size(&[]).is_err());
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
