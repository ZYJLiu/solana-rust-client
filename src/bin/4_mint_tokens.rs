// cargo run --bin 4_mint_tokens
use std::error::Error;

use keypair_utils::get_or_create_keypair;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, instruction::Instruction, signature::Signer,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::instruction::mint_to;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let mint = get_or_create_keypair("mint")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // Mint 100,000.00 tokens
    let amount = 100_000_00;

    // Associated token address of the sender
    let sender_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_1.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Instruction to mint tokens
    let mint_to_instruction: Instruction = mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),                   // Mint
        &sender_associated_token_address, // Token account to mint to
        &wallet_1.pubkey(),               // Token account owner
        &[&wallet_1.pubkey()],            // Additional signers (mint authority)
        amount,                           // Amount to mint
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[mint_to_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nMint Tokens: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );
    Ok(())
}
