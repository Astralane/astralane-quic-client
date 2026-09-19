## Astralane-quic-client

Rust client library for sending Solana transactions to Astralane's QUIC TPU endpoint.

### How It Works

The client authenticates using a self-signed TLS certificate with your API key as the Common Name (CN). On connect, the server extracts the CN from the certificate to identify your account. Transactions are multiplexed over QUIC unidirectional streams, one stream per transaction.

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
astralane-quic-client = { path = "../astralane-quic-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
anyhow = "1"
bincode = "1"
solana-sdk = "2"
```

### Quick Start

```rust
use astralane_quic_client::{
    AstralaneClientConfig, AstralaneQuicClient, SendCompletion, ServerIdentity,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect (certificate is generated automatically from your API key)
    let config = AstralaneClientConfig::new(
        "lim.gateway.astralane.io:7000",
        "your-api-key-uuid",
        ServerIdentity::InsecureSkipVerification,
    );
    let client = AstralaneQuicClient::connect(config).await?;

    // Build your transaction
    let transaction: solana_sdk::transaction::VersionedTransaction = /* ... */;
    // This example is legacy/v0. Use the Solana v1 wire codec for v1 transactions.
    let tx_bytes = bincode::serialize(&transaction)?;

    client
        .send_transaction_with_completion(&tx_bytes, SendCompletion::TransportAcknowledged)
        .await?;

    client.shutdown().await?;
    Ok(())
}
```

### API

**`AstralaneQuicClient::connect(config)`**

Connects using an `AstralaneClientConfig`. DNS resolution and connection establishment are bounded by `connect_timeout`; DNS is resolved again when reconnecting.

The client generates an EC P-256 certificate with `api_key` as the CN and configures ALPN as `astralane-tpu`. The client is cheaply cloneable; all clones share one endpoint and connection. Use `PinnedCertificate` in production. `InsecureSkipVerification` must be selected explicitly and should only be used when the server certificate cannot be verified.

**`client.send_transaction(&tx_bytes)`**

Sends a Solana wire-encoded `VersionedTransaction` and returns after the bytes and FIN are queued in Quinn. Legacy and v0 transactions are capped at 1232 bytes; v1 transactions are capped at 4096 bytes.

**`client.send_transaction_with_completion(&tx_bytes, completion)`**

Allows selecting `SendCompletion::Queued` or `SendCompletion::TransportAcknowledged`. Transport acknowledgment waits for the remote QUIC stack to acknowledge every byte. Neither mode confirms that Astralane processed or landed the transaction; that requires an application-level response.

**Automatic reconnection**: If the connection is dead (idle timeout, server restart, etc.), `send_transaction` will transparently reconnect before sending. No manual intervention needed.

**`client.is_connected()` / `client.is_closed()`**

Synchronous snapshots of the shared client state.

**`client.shutdown().await`**

Permanently shuts down the shared client and waits, up to `shutdown_timeout`, for the endpoint to become idle. Calls made after shutdown return `ClientError::Closed`. Dropping the last client clone performs a best-effort non-blocking close.

### Current Server Limits

| Parameter                  | Value      |
|----------------------------|------------|
| Max connections per API key| 10         |
| Max streams per connection | 64         |
| Stream timeout             | 750 ms     |
| Max transaction size       | 1232 bytes (legacy/v0), 4096 bytes (v1) |
| Idle timeout               | 30 s       |

### Error Codes

The server may close your connection with these application-level error codes:

| Code | Name                | Meaning                              |
|------|---------------------|--------------------------------------|
| 0    | OK                  | Normal closure                       |
| 1    | UNKNOWN_API_KEY     | API key not recognized               |
| 2    | CONNECTION_LIMIT    | Too many connections for this key    |

Use `astralane_quic_client::error_code::describe(code)` to get a human-readable description.

**Rate limiting**: When the rate limit is exceeded, the server silently drops excess transactions. The connection stays alive  - no error is returned to the client.

**Stream limits**: When the concurrent stream limit is reached, `open_uni()` applies backpressure until a stream slot frees up. If that takes longer than `stream_timeout`, the send returns `ClientError::StreamTimeout`.

### Error Handling

```rust
match client.send_transaction(&tx_bytes).await {
    Ok(_) => println!("Sent!"),
    Err(e) => {
        eprintln!("Error: {:?}", e);
        // Reconnection is automatic on the next send_transaction call.
        // Only fatal errors (e.g., UNKNOWN_API_KEY) require manual intervention.
    }
}
```

### Running the Example

The included example builds a signed transaction with compute budget instructions and a 0.0001 SOL tip transfer, then sends it via QUIC.

#### Environment Variables

| Variable       | Required | Description                                    | Default                                  |
|----------------|----------|------------------------------------------------|------------------------------------------|
| `API_KEY`      | Yes      | Your Astralane API key UUID                    |                                          |
| `KEYPAIR_PATH` | Yes      | Path to Solana keypair JSON file               |                                          |
| `TIP_ADDRESS`  | Yes      | Tip recipient pubkey (Astralane tip account)   |                                          |
| `RPC_URL`      | No       | Solana RPC URL (for fetching recent blockhash) | `https://api.mainnet-beta.solana.com`    |
| `SERVER_ADDR`  | Yes      | QUIC server address                            |                                          |

#### Run

```bash
RUST_LOG=info \
  API_KEY=your-api-key-uuid \
  KEYPAIR_PATH=~/.config/solana/id.json \
  TIP_ADDRESS=astrazznxsGUhWShqgNtAdfrzP2G83DzcWVJDxwV9bF \
  RPC_URL=https://api.mainnet-beta.solana.com \
  SERVER_ADDR=lim.gateway.astralane.io:7000 \
  cargo run --example send_transaction
```

#### What the Example Transaction Contains

1. `SetComputeUnitLimit`  - 20,000 CUs
2. `SetComputeUnitPrice`  - 10,000 micro-lamports per CU
3. `SystemProgram::Transfer`  - 0.0001 SOL (100,000 lamports) to the tip address
