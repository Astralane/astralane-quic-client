use anyhow::{Context, Result};
use astralane_quic_client::AstralaneQuicClient;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::hash::Hash;
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{EncodableKey, Keypair};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use solana_system_interface::instruction as system_instruction;
use std::env;
use std::str::FromStr;
use tracing::info;

async fn fetch_recent_blockhash(rpc_url: &str) -> Result<Hash> {
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{"commitment": "finalized"}]
    });

    let response = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .context("Failed to send RPC request")?;

    let json: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse RPC response")?;

    let blockhash_str = json["result"]["value"]["blockhash"]
        .as_str()
        .context("Missing blockhash in RPC response")?;

    Hash::from_str(blockhash_str).context("Failed to parse blockhash")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let api_key = env::var("API_KEY").expect("API_KEY env var required");
    let server = env::var("SERVER_ADDR").expect("SERVER_ADDR env var required");
    let rpc_url =
        env::var("RPC_URL").unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    let keypair_path =
        env::var("KEYPAIR_PATH").expect("KEYPAIR_PATH env var required (path to Solana keypair JSON)");
    let tip_address = env::var("TIP_ADDRESS").expect("TIP_ADDRESS env var required (Solana pubkey)");

    let tip_account = Pubkey::from_str(&tip_address)?;

    // Load keypair from JSON file
    let payer = Keypair::read_from_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("Failed to read keypair from {}: {}", keypair_path, e))?;
    info!("Payer pubkey: {}", payer.pubkey());

    // Fetch recent blockhash from RPC
    info!("Fetching recent blockhash from {} ...", rpc_url);
    let recent_blockhash = fetch_recent_blockhash(&rpc_url).await?;
    info!("Recent blockhash: {}", recent_blockhash);

    info!("Connecting to {} with API key {}...", server, api_key);
    let client = AstralaneQuicClient::connect(&server, &api_key).await?;
    info!("Connected!");

    // Build transaction instructions
    let instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(20_000),
        ComputeBudgetInstruction::set_compute_unit_price(10_000),
        system_instruction::transfer(&payer.pubkey(), &tip_account, 100_000),
    ];

    let message = Message::new(&instructions, Some(&payer.pubkey()));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.sign(&[&payer], recent_blockhash);

    let tx_bytes = bincode::serialize(&transaction)?;
    let sig = transaction.signatures[0];
    info!(
        "[CLIENT] Sending transaction: sig={}, size={} bytes",
        sig,
        tx_bytes.len()
    );

    match client.send_transaction(&tx_bytes).await {
        Ok(_) => info!("[CLIENT] Transaction sent successfully! sig={}", sig),
        Err(e) => tracing::error!("[CLIENT] Failed to send transaction: {:?}", e),
    }

    // Allow server to finish reading the stream before closing
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    client.close().await;
    info!("Done!");
    Ok(())
}
