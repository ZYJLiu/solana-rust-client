// cargo run --bin 5_deposit_tokens
use keypair_utils::get_or_create_keypair;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, signature::Signer, transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::extension::confidential_transfer::instruction::deposit;
use std::error::Error;

// Token accounts with Confidential extension enabled have separate "pending" and "available" balances
// Token account owner must first "deposit" tokens from non-confidential balance to "pending" confidential balance
fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let mint = get_or_create_keypair("mint")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // Amount to deposit, 100,000.00 tokens
    let deposit_amount = 100_000_00;
    // Mint decimals
    let decimals = 2;

    // Associated token address of the sender
    let sender_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_1.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Instruction to deposit from non-confidential balance to "pending" balance
    let deposit_instruction = deposit(
        &spl_token_2022::id(),
        &sender_associated_token_address, // Token account
        &mint.pubkey(),                   // Mint
        deposit_amount,                   // Amount to deposit
        decimals,                         // Mint decimals
        &wallet_1.pubkey(),               // Token account owner
        &[&wallet_1.pubkey()],            // Signers
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[deposit_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nDeposit Tokens: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );
    Ok(())
}
