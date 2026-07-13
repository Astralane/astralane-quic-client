//! End-to-end tests against a local QUIC server that stands in for the Astralane
//! gateway: same ALPN, same self-signed setup, and it authenticates by reading the
//! client certificate's CN rather than validating a chain.

use anyhow::Result;
use astralane_quic_client::{AstralaneQuicClient, MAX_TRANSACTION_SIZE};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Accepts any client certificate. The gateway identifies callers by the CN it
/// finds in the cert, so there is no chain to validate.
#[derive(Debug)]
struct AcceptAnyClientCert;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
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
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Spawns a gateway-alike server. Every transaction it manages to read is pushed
/// onto the returned channel.
///
/// `read_delay` models the gap between a stream arriving and the gateway actually
/// draining it — real forwarders are not infinitely fast, and a client that tears
/// the connection down inside that window loses the transaction.
fn spawn_server(read_delay: Duration) -> Result<(SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>)> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = CertificateParams::new(vec!["astralane".to_string()])?.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
        .with_single_cert(vec![cert_der], key_der)?;
    crypto.alpn_protocols = vec![b"astralane-tpu".to_vec()];

    let endpoint = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?)),
        "127.0.0.1:0".parse()?,
    )?;
    let addr = endpoint.local_addr()?;

    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok(mut recv) = conn.accept_uni().await {
                    tokio::time::sleep(read_delay).await;
                    if let Ok(bytes) = recv.read_to_end(MAX_TRANSACTION_SIZE).await {
                        let _ = tx.send(bytes);
                    }
                }
            });
        }
    });

    Ok((addr, rx))
}

/// Regression test for #1: the client reported "sent successfully" but the
/// transaction never reached the server.
///
/// `send_transaction` must not return until the server has acknowledged the bytes,
/// otherwise the `close()` that follows discards a transaction that was never
/// actually put on the wire.
#[tokio::test]
async fn transaction_arrives_when_client_closes_immediately_after_send() -> Result<()> {
    let (addr, mut rx) = spawn_server(Duration::from_millis(200))?;

    let client = AstralaneQuicClient::connect(&addr.to_string(), "test-api-key").await?;

    let transaction = vec![7u8; 215];
    client.send_transaction(&transaction).await?;
    client.close().await;

    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("server never received the transaction"))?
        .ok_or_else(|| anyhow::anyhow!("server channel closed"))?;

    assert_eq!(received, transaction, "server received corrupted bytes");
    Ok(())
}

/// The client must survive being dropped without an explicit `close()`.
#[tokio::test]
async fn transaction_arrives_when_client_is_dropped() -> Result<()> {
    let (addr, mut rx) = spawn_server(Duration::from_millis(200))?;

    let client = AstralaneQuicClient::connect(&addr.to_string(), "test-api-key").await?;

    let transaction = vec![9u8; 180];
    client.send_transaction(&transaction).await?;
    drop(client);

    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("server never received the transaction"))?
        .ok_or_else(|| anyhow::anyhow!("server channel closed"))?;

    assert_eq!(received, transaction);
    Ok(())
}

#[tokio::test]
async fn oversized_transaction_is_rejected() -> Result<()> {
    let (addr, _rx) = spawn_server(Duration::ZERO)?;
    let client = AstralaneQuicClient::connect(&addr.to_string(), "test-api-key").await?;

    let err = client
        .send_transaction(&vec![0u8; MAX_TRANSACTION_SIZE + 1])
        .await
        .expect_err("oversized transaction should be rejected");

    assert!(err.to_string().contains("too large"), "got: {err}");
    Ok(())
}
