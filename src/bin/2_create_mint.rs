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

// Create a mint account with the `ConfidentialTransferMint` extension
fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;

    let mint = get_or_create_keypair("mint")?;
    let decimals = 2;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    let auditor_elgamal_keypair = ElGamalKeypair::new_rand();
    let confidential_transfer_mint_extension =
        ExtensionInitializationParams::ConfidentialTransferMint {
            authority: Some(wallet_1.pubkey()),
            auto_approve_new_accounts: true,
            auditor_elgamal_pubkey: Some((*auditor_elgamal_keypair.pubkey()).into()),
        };

    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let create_account_instruction = create_account(
        &wallet_1.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    let extension_instruction =
        confidential_transfer_mint_extension.instruction(&spl_token_2022::id(), &mint.pubkey())?;

    let initialize_mint_instruction = initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &wallet_1.pubkey(),       // Mint authority
        Some(&wallet_1.pubkey()), // Freeze authority
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
