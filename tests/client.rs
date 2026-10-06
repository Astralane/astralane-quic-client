use anyhow::Result;
use astralane_quic_client::{
    AstralaneClientConfig, AstralaneQuicClient, ClientError, SendCompletion, ServerIdentity,
};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug)]
struct AcceptAnyClientCertificate;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCertificate {
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
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

type TestServer = (
    SocketAddr,
    CertificateDer<'static>,
    mpsc::UnboundedReceiver<Vec<u8>>,
    Arc<AtomicUsize>,
);

fn spawn_server(close_first_after: Option<Duration>) -> Result<TestServer> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = CertificateParams::new(vec!["astralane".to_string()])?.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCertificate))
        .with_single_cert(vec![cert_der.clone()], key_der)?;
    crypto.alpn_protocols = vec![b"astralane-tpu".to_vec()];

    let endpoint = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?)),
        "127.0.0.1:0".parse()?,
    )?;
    let address = endpoint.local_addr()?;
    let (sender, receiver) = mpsc::unbounded_channel();
    let connection_count = Arc::new(AtomicUsize::new(0));
    let task_connection_count = connection_count.clone();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let sender = sender.clone();
            let connection_index = task_connection_count.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                if connection_index == 0 {
                    if let Some(delay) = close_first_after {
                        tokio::time::sleep(delay).await;
                        connection.close(0u32.into(), b"test reconnect");
                        return;
                    }
                }
                while let Ok(mut stream) = connection.accept_uni().await {
                    if let Ok(bytes) = stream.read_to_end(4_104).await {
                        let _ = sender.send(bytes);
                    }
                }
            });
        }
    });

    Ok((address, cert_der, receiver, connection_count))
}

async fn connect_client(
    address: SocketAddr,
    certificate: CertificateDer<'static>,
) -> Result<AstralaneQuicClient> {
    let mut config = AstralaneClientConfig::new(
        address.to_string(),
        "test-api-key",
        ServerIdentity::PinnedCertificate(certificate),
    );
    config.connect_timeout = Duration::from_secs(2);
    config.stream_timeout = Duration::from_secs(2);
    config.shutdown_timeout = Duration::from_secs(2);
    Ok(AstralaneQuicClient::connect(config).await?)
}

#[tokio::test]
async fn transport_acknowledged_send_reaches_peer() -> Result<()> {
    let (address, certificate, mut received, _) = spawn_server(None)?;
    let client = connect_client(address, certificate).await?;
    let transaction = vec![7; 215];

    client
        .send_transaction_with_completion(&transaction, SendCompletion::TransportAcknowledged)
        .await?;

    assert_eq!(
        received.recv().await.as_deref(),
        Some(transaction.as_slice())
    );
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn signed_sdk5_transactions_reach_peer_unchanged() -> Result<()> {
    use solana_sdk::hash::Hash;
    use solana_sdk::instruction::Instruction;
    use solana_sdk::message::{v0, v1, Message, VersionedMessage};
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::signature::{Keypair, Signer};
    use solana_system_interface::instruction::transfer;
    use solana_transaction::versioned::VersionedTransaction;

    let (address, certificate, mut received, _) = spawn_server(None)?;
    let client = connect_client(address, certificate).await?;
    let payer = Keypair::new();
    let blockhash = Hash::new_from_array([42; 32]);
    let instructions = vec![transfer(&payer.pubkey(), &Pubkey::new_unique(), 100_000)];
    let config = v1::TransactionConfig {
        priority_fee: Some(200),
        compute_unit_limit: Some(1_400_000),
        loaded_accounts_data_size_limit: Some(1_048_576),
        heap_size: None,
    };
    let mut messages = vec![
        VersionedMessage::Legacy(Message::new_with_blockhash(
            &instructions,
            Some(&payer.pubkey()),
            &blockhash,
        )),
        VersionedMessage::V0(v0::Message::try_compile(
            &payer.pubkey(),
            &instructions,
            &[],
            blockhash,
        )?),
        VersionedMessage::V1(v1::Message::try_compile_with_config(
            &payer.pubkey(),
            &instructions,
            blockhash,
            config,
        )?),
    ];

    for target_size in [1_772, 4_096] {
        let mut large_instructions = instructions.clone();
        large_instructions.push(Instruction::new_with_bytes(
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".parse()?,
            &vec![b'x'; 1_500],
            vec![],
        ));
        let message = v1::Message::try_compile_with_config(
            &payer.pubkey(),
            &large_instructions,
            blockhash,
            config,
        )?;
        let transaction = VersionedTransaction::try_new(VersionedMessage::V1(message), &[&payer])?;
        let initial_size = wincode::serialize(&transaction)?.len();
        large_instructions[1]
            .data
            .resize(1_500 + target_size - initial_size, b'x');
        messages.push(VersionedMessage::V1(v1::Message::try_compile_with_config(
            &payer.pubkey(),
            &large_instructions,
            blockhash,
            config,
        )?));
    }

    for (index, message) in messages.into_iter().enumerate() {
        let transaction = VersionedTransaction::try_new(message, &[&payer])?;
        transaction.sanitize()?;
        transaction.verify_and_hash_message()?;
        let wire = wincode::serialize(&transaction)?;
        if index >= 2 {
            assert_eq!(wire[0], 0x81);
        }
        if index >= 3 {
            assert_eq!(wire.len(), [1_772, 4_096][index - 3]);
        }

        for completion in [
            SendCompletion::Queued,
            SendCompletion::TransportAcknowledged,
        ] {
            client
                .send_transaction_with_completion(&wire, completion)
                .await?;
            let frame = tokio::time::timeout(Duration::from_secs(2), received.recv())
                .await?
                .expect("server should receive the signed transaction");
            assert_eq!(frame, wire);
            let decoded: VersionedTransaction = wincode::deserialize(&frame)?;
            assert_eq!(decoded, transaction);
            decoded.verify_and_hash_message()?;
        }

        if wire.len() == 4_096 {
            let mut oversized = wire;
            oversized.push(0);
            assert!(matches!(
                client.send_transaction(&oversized).await,
                Err(ClientError::TransactionTooLarge {
                    actual: 4_097,
                    maximum: 4_096,
                    ..
                })
            ));
        }
    }
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn ghost_send_writes_tip_before_transaction() -> Result<()> {
    let (address, certificate, mut received, _) = spawn_server(None)?;
    let client = connect_client(address, certificate).await?;
    let transaction = vec![9; 180];

    client
        .send_ghost_transaction_with_completion(
            42,
            &transaction,
            SendCompletion::TransportAcknowledged,
        )
        .await?;

    let frame = received
        .recv()
        .await
        .expect("server should receive a frame");
    assert_eq!(&frame[..8], &42u64.to_le_bytes());
    assert_eq!(&frame[8..], transaction);
    client.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn shutdown_is_shared_and_terminal() -> Result<()> {
    let (address, certificate, _received, _) = spawn_server(None)?;
    let client = connect_client(address, certificate).await?;
    let clone = client.clone();

    let (first_shutdown, second_shutdown) = tokio::join!(client.shutdown(), clone.shutdown());
    first_shutdown?;
    second_shutdown?;

    assert!(clone.is_closed());
    assert!(!clone.is_connected());
    assert!(matches!(
        clone.send_transaction(&[1]).await,
        Err(ClientError::Closed)
    ));
    Ok(())
}

#[tokio::test]
async fn concurrent_sends_share_one_reconnect() -> Result<()> {
    let (address, certificate, _received, connection_count) =
        spawn_server(Some(Duration::from_millis(700)))?;
    let client = connect_client(address, certificate).await?;

    tokio::time::timeout(Duration::from_secs(2), async {
        while client.is_connected() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;

    let mut sends = Vec::new();
    for _ in 0..16 {
        let client = client.clone();
        sends.push(tokio::spawn(
            async move { client.send_transaction(&[1]).await },
        ));
    }
    for send in sends {
        send.await??;
    }

    assert_eq!(connection_count.load(Ordering::Relaxed), 2);
    client.shutdown().await?;
    Ok(())
}
