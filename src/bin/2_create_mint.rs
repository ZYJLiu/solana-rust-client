// cargo run --bin 2_create_mint
use keypair_utils::get_or_create_keypair;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, signature::Signer, system_instruction::create_account,
    transaction::Transaction,
};
use spl_token_2022::{
    extension::ExtensionType, instruction::initialize_mint,
    solana_zk_token_sdk::encryption::elgamal::ElGamalKeypair, state::Mint,
};
use spl_token_client::token::ExtensionInitializationParams;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    let mint = get_or_create_keypair("mint")?;
    let mint_authority = &wallet_1;
    let freeze_authority = &wallet_1;
    let decimals = 2;

    // Confidential Transfer Extension authority
    // Authority to modify the `ConfidentialTransferMint` configuration and to approve new accounts (if `auto_approve_new_accounts` is false?)
    let authority = &wallet_1;

    // Auditor ElGamal pubkey
    // Authority to decode any transfer amount in a confidential transfer
    let auditor_elgamal_keypair = ElGamalKeypair::new_rand();

    // ConfidentialTransferMint extension parameters
    let confidential_transfer_mint_extension =
        ExtensionInitializationParams::ConfidentialTransferMint {
            authority: Some(authority.pubkey()),
            auto_approve_new_accounts: true, // If `true`, no approval is required and new accounts may be used immediately
            auditor_elgamal_pubkey: Some((*auditor_elgamal_keypair.pubkey()).into()),
        };

    // Calculate the space required for the mint account with the extension
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;

    // Calculate the lamports required for the mint account
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Instructions to create the mint account
    let create_account_instruction = create_account(
        &wallet_1.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    // ConfidentialTransferMint extension instruction
    let extension_instruction =
        confidential_transfer_mint_extension.instruction(&spl_token_2022::id(), &mint.pubkey())?;

    // Initialize the mint account
    let initialize_mint_instruction = initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &mint_authority.pubkey(),
        Some(&freeze_authority.pubkey()),
        decimals,
    )?;

    let instructions = vec![
        create_account_instruction,
        extension_instruction,
        initialize_mint_instruction,
    ];

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &mint],
        recent_blockhash,
    );
    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Mint Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );
    Ok(())
}
