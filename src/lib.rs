use arc_swap::ArcSwap;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, trace, warn};

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

fn validate_transaction_size(transaction_bytes: &[u8]) -> Result<(), ClientError> {
    if transaction_bytes.is_empty() {
        return Err(ClientError::EmptyTransaction);
    }

    let max_size = transaction_size_limit(transaction_bytes);
    if transaction_bytes.len() > max_size {
        return Err(ClientError::TransactionTooLarge {
            actual: transaction_bytes.len(),
            maximum: max_size,
            version: if max_size == MAX_V1_TRANSACTION_SIZE {
                TransactionVersion::V1
            } else {
                TransactionVersion::LegacyOrV0
            },
        });
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

/// Delay after reconnecting to verify the server accepted the connection
/// (server's post-handshake close frame may be in flight).
const RECONNECT_VERIFY_DELAY: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionVersion {
    LegacyOrV0,
    V1,
}

impl std::fmt::Display for TransactionVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyOrV0 => formatter.write_str("legacy/v0"),
            Self::V1 => formatter.write_str("v1"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SendCompletion {
    #[default]
    Queued,
    TransportAcknowledged,
}

#[derive(Clone)]
pub enum ServerIdentity {
    PinnedCertificate(CertificateDer<'static>),
    InsecureSkipVerification,
}

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_connection_limit_retries: u32,
    pub reconnect_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_connection_limit_retries: 3,
            reconnect_delay: Duration::from_secs(30),
        }
    }
}

#[derive(Clone)]
pub struct AstralaneClientConfig {
    pub server_addr: String,
    pub server_name: String,
    pub api_key: String,
    pub server_identity: ServerIdentity,
    pub connect_timeout: Duration,
    pub stream_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub retry_policy: RetryPolicy,
}

impl AstralaneClientConfig {
    pub fn new(
        server_addr: impl Into<String>,
        api_key: impl Into<String>,
        server_identity: ServerIdentity,
    ) -> Self {
        Self {
            server_addr: server_addr.into(),
            server_name: "astralane".to_string(),
            api_key: api_key.into(),
            server_identity,
            connect_timeout: Duration::from_secs(10),
            stream_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(5),
            retry_policy: RetryPolicy::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("client is closed")]
    Closed,
    #[error("transaction payload is empty")]
    EmptyTransaction,
    #[error("transaction is {actual} bytes, exceeding the {maximum}-byte {version} limit")]
    TransactionTooLarge {
        actual: usize,
        maximum: usize,
        version: TransactionVersion,
    },
    #[error("failed to resolve {address}: {message}")]
    ResolveAddress { address: String, message: String },
    #[error("resolving {address} timed out")]
    ResolveTimeout { address: String },
    #[error("failed to configure the client: {0}")]
    Configuration(String),
    #[error("failed to create the QUIC endpoint: {0}")]
    Endpoint(String),
    #[error("failed to begin connecting: {0}")]
    ConnectSetup(String),
    #[error("connection attempt timed out")]
    ConnectTimeout,
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("unknown API key")]
    UnknownApiKey,
    #[error("connection limit reached after {attempts} retries")]
    ConnectionLimit { attempts: u32 },
    #[error("timed out waiting for stream capacity")]
    StreamTimeout,
    #[error("failed to open a unidirectional stream: {0}")]
    OpenStream(String),
    #[error("failed to write transaction data: {0}")]
    Write(String),
    #[error("failed to finish the stream: {0}")]
    Finish(String),
    #[error("timed out waiting for transport acknowledgement")]
    AcknowledgementTimeout,
    #[error("the peer stopped the stream with code {0}")]
    StreamStopped(u64),
    #[error("transport acknowledgement failed: {0}")]
    Acknowledgement(String),
    #[error("timed out waiting for the QUIC endpoint to shut down")]
    ShutdownTimeout,
}

/// A cloneable QUIC client for sending transactions to Astralane's TPU endpoint.
#[derive(Clone)]
pub struct AstralaneQuicClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    endpoint: Endpoint,
    connection: ArcSwap<Connection>,
    reconnect_lock: Mutex<()>,
    config: AstralaneClientConfig,
    reconnect_attempts: AtomicU32,
    closed: AtomicBool,
}

impl AstralaneQuicClient {
    pub async fn connect(config: AstralaneClientConfig) -> Result<Self, ClientError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client_config = Self::build_client_config(&config)?;

        let mut endpoint = Endpoint::client(
            "0.0.0.0:0"
                .parse::<SocketAddr>()
                .map_err(|error| ClientError::Endpoint(error.to_string()))?,
        )
        .map_err(|error| ClientError::Endpoint(error.to_string()))?;
        endpoint.set_default_client_config(client_config);

        let connection = Self::create_connection_with_retry(&endpoint, &config).await?;
        info!("[CLIENT] Connected to Astralane QUIC server");

        Ok(Self {
            inner: Arc::new(ClientInner {
                endpoint,
                connection: ArcSwap::new(connection),
                reconnect_lock: Mutex::new(()),
                config,
                reconnect_attempts: AtomicU32::new(0),
                closed: AtomicBool::new(false),
            }),
        })
    }

    pub async fn send_transaction(&self, transaction_bytes: &[u8]) -> Result<(), ClientError> {
        self.send_transaction_with_completion(transaction_bytes, SendCompletion::Queued)
            .await
    }

    pub async fn send_transaction_with_completion(
        &self,
        transaction_bytes: &[u8],
        completion: SendCompletion,
    ) -> Result<(), ClientError> {
        validate_transaction_size(transaction_bytes)?;
        self.send_frame(None, transaction_bytes, completion).await
    }

    pub async fn send_ghost_transaction(
        &self,
        tip_lamports: u64,
        transaction_bytes: &[u8],
    ) -> Result<(), ClientError> {
        self.send_ghost_transaction_with_completion(
            tip_lamports,
            transaction_bytes,
            SendCompletion::Queued,
        )
        .await
    }

    pub async fn send_ghost_transaction_with_completion(
        &self,
        tip_lamports: u64,
        transaction_bytes: &[u8],
        completion: SendCompletion,
    ) -> Result<(), ClientError> {
        validate_transaction_size(transaction_bytes)?;
        self.send_frame(
            Some(tip_lamports.to_le_bytes()),
            transaction_bytes,
            completion,
        )
        .await
    }

    async fn send_frame(
        &self,
        prefix: Option<[u8; 8]>,
        transaction_bytes: &[u8],
        completion: SendCompletion,
    ) -> Result<(), ClientError> {
        self.ensure_open()?;
        let mut send_stream = self.open_stream().await?;

        let write = async {
            if let Some(prefix) = prefix {
                send_stream
                    .write_all(&prefix)
                    .await
                    .map_err(|error| ClientError::Write(error.to_string()))?;
            }
            send_stream
                .write_all(transaction_bytes)
                .await
                .map_err(|error| ClientError::Write(error.to_string()))
        };
        match tokio::time::timeout(self.inner.config.stream_timeout, write).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = send_stream.reset(0u32.into());
                return Err(ClientError::StreamTimeout);
            }
        }

        send_stream
            .finish()
            .map_err(|error| ClientError::Finish(error.to_string()))?;

        if completion == SendCompletion::TransportAcknowledged {
            match tokio::time::timeout(self.inner.config.stream_timeout, send_stream.stopped())
                .await
                .map_err(|_| ClientError::AcknowledgementTimeout)?
                .map_err(|error| ClientError::Acknowledgement(error.to_string()))?
            {
                None => {}
                Some(code) => return Err(ClientError::StreamStopped(code.into_inner())),
            }
        }

        trace!(
            "[CLIENT] Transaction frame sent ({} bytes)",
            transaction_bytes.len() + prefix.map_or(0, |_| 8)
        );

        Ok(())
    }

    async fn open_stream(&self) -> Result<quinn::SendStream, ClientError> {
        for attempt in 0..2 {
            let connection = self.get_or_create_connection().await?;
            match tokio::time::timeout(self.inner.config.stream_timeout, connection.open_uni())
                .await
            {
                Err(_) => return Err(ClientError::StreamTimeout),
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(_)) if attempt == 0 => continue,
                Ok(Err(error)) => return Err(ClientError::OpenStream(error.to_string())),
            }
        }
        unreachable!()
    }

    async fn get_or_create_connection(&self) -> Result<Arc<Connection>, ClientError> {
        self.ensure_open()?;
        let connection = self.inner.connection.load_full();
        if connection.close_reason().is_none() {
            return Ok(connection);
        }

        let _reconnect_guard = self.inner.reconnect_lock.lock().await;
        self.ensure_open()?;
        let connection = self.inner.connection.load_full();
        let Some(reason) = connection.close_reason() else {
            return Ok(connection);
        };

        if application_error_code(&reason) == Some(error_code::UNKNOWN_API_KEY as u64) {
            return Err(ClientError::UnknownApiKey);
        }

        if application_error_code(&reason) == Some(error_code::CONNECTION_LIMIT as u64) {
            let attempts = self.inner.reconnect_attempts.load(Ordering::Relaxed);
            if attempts >= self.inner.config.retry_policy.max_connection_limit_retries {
                self.close_endpoint();
                return Err(ClientError::ConnectionLimit { attempts });
            }
            warn!(
                "[CLIENT] Connection limit reached, reconnect attempt {}/{} in {}s",
                attempts + 1,
                self.inner.config.retry_policy.max_connection_limit_retries,
                self.inner.config.retry_policy.reconnect_delay.as_secs()
            );
            tokio::time::sleep(self.inner.config.retry_policy.reconnect_delay).await;
            self.ensure_open()?;
        } else {
            warn!("[CLIENT] Connection dead, reconnecting");
        }

        let connection = Self::create_connection(&self.inner.endpoint, &self.inner.config).await?;
        self.ensure_open_or_close(&connection)?;
        let close_reason = connection.close_reason();
        self.inner.connection.store(connection.clone());

        if let Some(reason) = close_reason {
            let attempts =
                if application_error_code(&reason) == Some(error_code::CONNECTION_LIMIT as u64) {
                    self.inner
                        .reconnect_attempts
                        .fetch_add(1, Ordering::Relaxed)
                        + 1
                } else {
                    self.inner.reconnect_attempts.load(Ordering::Relaxed)
                };
            return Err(client_error_from_close_reason(&reason, attempts));
        }

        self.inner.reconnect_attempts.store(0, Ordering::Relaxed);
        info!("[CLIENT] Reconnected to Astralane QUIC server");
        Ok(connection)
    }

    pub fn is_connected(&self) -> bool {
        !self.is_closed() && self.inner.connection.load().close_reason().is_none()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub async fn shutdown(&self) -> Result<(), ClientError> {
        self.close_endpoint();
        tokio::time::timeout(
            self.inner.config.shutdown_timeout,
            self.inner.endpoint.wait_idle(),
        )
        .await
        .map_err(|_| ClientError::ShutdownTimeout)?;
        Ok(())
    }

    fn close_endpoint(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner
            .endpoint
            .close(error_code::OK.into(), b"client closing");
    }

    fn ensure_open(&self) -> Result<(), ClientError> {
        if self.is_closed() {
            Err(ClientError::Closed)
        } else {
            Ok(())
        }
    }

    fn ensure_open_or_close(&self, connection: &Connection) -> Result<(), ClientError> {
        if self.is_closed() {
            connection.close(error_code::OK.into(), b"client closing");
            Err(ClientError::Closed)
        } else {
            Ok(())
        }
    }

    async fn create_connection_with_retry(
        endpoint: &Endpoint,
        config: &AstralaneClientConfig,
    ) -> Result<Arc<Connection>, ClientError> {
        let maximum_retries = config.retry_policy.max_connection_limit_retries;

        for attempt in 0..=maximum_retries {
            let connection = Self::create_connection(endpoint, config).await?;
            let Some(reason) = connection.close_reason() else {
                return Ok(connection);
            };

            match application_error_code(&reason) {
                Some(code) if code == error_code::UNKNOWN_API_KEY as u64 => {
                    return Err(ClientError::UnknownApiKey);
                }
                Some(code) if code == error_code::CONNECTION_LIMIT as u64 => {
                    if attempt == maximum_retries {
                        return Err(ClientError::ConnectionLimit { attempts: attempt });
                    }

                    warn!(
                        "[CLIENT] Connection limit reached, retry {}/{} in {}s",
                        attempt + 1,
                        maximum_retries,
                        config.retry_policy.reconnect_delay.as_secs()
                    );
                    tokio::time::sleep(config.retry_policy.reconnect_delay).await;
                }
                _ => return Err(client_error_from_close_reason(&reason, attempt)),
            }
        }

        unreachable!()
    }

    async fn create_connection(
        endpoint: &Endpoint,
        config: &AstralaneClientConfig,
    ) -> Result<Arc<Connection>, ClientError> {
        let address = tokio::time::timeout(
            config.connect_timeout,
            tokio::net::lookup_host(config.server_addr.as_str()),
        )
        .await
        .map_err(|_| ClientError::ResolveTimeout {
            address: config.server_addr.clone(),
        })?
        .map_err(|error| ClientError::ResolveAddress {
            address: config.server_addr.clone(),
            message: error.to_string(),
        })?
        .next()
        .ok_or_else(|| ClientError::ResolveAddress {
            address: config.server_addr.clone(),
            message: "no addresses returned".to_string(),
        })?;

        let connecting = endpoint
            .connect(address, &config.server_name)
            .map_err(|error| ClientError::ConnectSetup(error.to_string()))?;
        let connection = tokio::time::timeout(config.connect_timeout, connecting)
            .await
            .map_err(|_| ClientError::ConnectTimeout)?
            .map_err(|error| ClientError::Connect(error.to_string()))?;

        // The QUIC handshake can complete before the server's asynchronous authentication
        // rejection arrives. Keep the connection private during this verification window.
        tokio::time::sleep(RECONNECT_VERIFY_DELAY).await;
        Ok(Arc::new(connection))
    }

    fn build_client_config(
        config: &AstralaneClientConfig,
    ) -> Result<QuinnClientConfig, ClientError> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|error| ClientError::Configuration(error.to_string()))?;
        let mut cert_params = CertificateParams::new(vec![])
            .map_err(|error| ClientError::Configuration(error.to_string()))?;
        cert_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String(config.api_key.clone()),
        );
        let cert = cert_params
            .self_signed(&key_pair)
            .map_err(|error| ClientError::Configuration(error.to_string()))?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let builder = rustls::ClientConfig::builder();
        let mut crypto = match &config.server_identity {
            ServerIdentity::PinnedCertificate(server_certificate) => {
                let mut roots = rustls::RootCertStore::empty();
                roots
                    .add(server_certificate.clone())
                    .map_err(|error| ClientError::Configuration(error.to_string()))?;
                builder
                    .with_root_certificates(roots)
                    .with_client_auth_cert(vec![cert_der], key_der)
            }
            ServerIdentity::InsecureSkipVerification => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_client_auth_cert(vec![cert_der], key_der),
        }
        .map_err(|error| ClientError::Configuration(error.to_string()))?;

        crypto.alpn_protocols = vec![ALPN_ASTRALANE_TPU.to_vec()];

        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(25)));

        let quic_crypto = QuicClientConfig::try_from(crypto)
            .map_err(|error| ClientError::Configuration(error.to_string()))?;
        let mut client_config = QuinnClientConfig::new(Arc::new(quic_crypto));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.connection
            .load()
            .close(error_code::OK.into(), b"client closing");
    }
}

fn application_error_code(reason: &quinn::ConnectionError) -> Option<u64> {
    match reason {
        quinn::ConnectionError::ApplicationClosed(info) => Some(info.error_code.into_inner()),
        _ => None,
    }
}

fn client_error_from_close_reason(reason: &quinn::ConnectionError, attempts: u32) -> ClientError {
    match application_error_code(reason) {
        Some(code) if code == error_code::UNKNOWN_API_KEY as u64 => ClientError::UnknownApiKey,
        Some(code) if code == error_code::CONNECTION_LIMIT as u64 => {
            ClientError::ConnectionLimit { attempts }
        }
        _ => ClientError::Connect(reason.to_string()),
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

    #[test]
    fn ghost_tip_does_not_reduce_the_v1_limit() {
        let mut transaction = vec![0u8; MAX_V1_TRANSACTION_SIZE];
        transaction[0] = V1_TRANSACTION_PREFIX;
        assert!(validate_transaction_size(&transaction).is_ok());
        assert_eq!(42u64.to_le_bytes().len() + transaction.len(), 4104);
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
