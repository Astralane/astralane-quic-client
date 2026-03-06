## Astralane-quic-client

Rust client library for sending Solana transactions to Astralane's QUIC TPU endpoint.

### How It Works

The client authenticates using a self-signed TLS certificate with your API key as the Common Name (CN). On connect, the server extracts the CN from the certificate to identify your account. Transactions are sent as fire-and-forget over QUIC unidirectional streams  - one stream per transaction.

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
use astralane_quic_client::AstralaneQuicClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect (certificate is generated automatically from your API key)
    let client = AstralaneQuicClient::connect("lim.gateway.astralane.io:7000", "your-api-key-uuid").await?;

    // Build your transaction
    let transaction: solana_sdk::transaction::VersionedTransaction = /* ... */;
    let tx_bytes = bincode::serialize(&transaction)?;

    // Send (fire-and-forget)
    client.send_transaction(&tx_bytes).await?;

    Ok(())
}
```

### API

**`AstralaneQuicClient::connect(server_addr, api_key)`**

Connects to the QUIC server. Accepts both IP:port (`"1.2.3.4:7000"`) and hostname:port (`"lim.gateway.astralane.io:7000"`) formats.

Internally generates an EC P-256 self-signed certificate with `api_key` as the CN, configures ALPN as `astralane-tpu`, and establishes a single QUIC connection with 25s keep-alive. Each client instance holds exactly one connection  - all `send_transaction` calls are multiplexed as separate streams over it. Create multiple client instances if you need more concurrent connections (up to the server's per-API-key connection limit).

**`client.send_transaction(&tx_bytes)`**

Sends a bincode-serialized `VersionedTransaction` (max 1232 bytes). Opens a unidirectional QUIC stream, writes the bytes, and finishes the stream. Fire-and-forget  - returns `Ok(())` once written, with no server response.

**Automatic reconnection**: If the connection is dead (idle timeout, server restart, etc.), `send_transaction` will transparently reconnect before sending. No manual intervention needed.

**`client.reconnect().await`**

Manually reconnects if the connection was closed. Typically not needed since `send_transaction` reconnects automatically.

**`client.is_connected().await`**

Returns `true` if the connection is still alive.

**`client.close().await`**

Gracefully closes the connection. Also called automatically on drop.

**Important:** `close()` sends a QUIC `CONNECTION_CLOSE` frame that immediately terminates all open streams. If you've just sent transactions, add a short delay before closing to let the server finish reading in-flight streams:

```rust
tokio::time::sleep(std::time::Duration::from_millis(100)).await;
client.close().await;
```

### Current Server Limits

| Parameter                  | Value      |
|----------------------------|------------|
| Max connections per API key| 10         |
| Max streams per connection | 64         |
| Stream timeout             | 750 ms     |
| Max transaction size       | 1232 bytes |
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

**Stream limits**: When the concurrent stream limit is reached, `open_uni()` blocks (backpressure) until a stream slot frees up. The server does not close the connection  - `send_transaction` will simply take longer to return.

### Error Handling

```rust
// send_transaction automatically reconnects if the connection is dead.
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
