// cargo run --bin 7_create_recipient_account
use keypair_utils::get_or_create_keypair;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, signature::Signer, transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::{
    error::TokenError,
    extension::{confidential_transfer::instruction::configure_account, ExtensionType},
    instruction::reallocate,
    proof::ProofLocation,
    solana_zk_token_sdk::{
        encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
        zk_token_proof_instruction::PubkeyValidityData,
    },
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wallet_2 = get_or_create_keypair("wallet_2")?;
    let mint = get_or_create_keypair("mint")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // Associated token address of the recipient
    let recipient_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_2.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Instruction to create associated token account
    let create_associated_token_account_instruction = create_associated_token_account(
        &wallet_2.pubkey(), // Funding account
        &wallet_2.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Instruction to reallocate the token account to include the `ConfidentialTransferAccount` extension
    let reallocate_instruction = reallocate(
        &spl_token_2022::id(),
        &recipient_associated_token_address,
        &wallet_2.pubkey(),    // payer
        &wallet_2.pubkey(),    // owner
        &[&wallet_2.pubkey()], // signers
        &[ExtensionType::ConfidentialTransferAccount],
    )?;

    // Create the ElGamal keypair and AES key for the recipient token account
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_2, &recipient_associated_token_address.to_bytes())
            .unwrap();
    let aes_key =
        AeKey::new_from_signer(&wallet_2, &recipient_associated_token_address.to_bytes()).unwrap();

    let maximum_pending_balance_credit_counter = 65536; // Default value or custom
    let decryptable_balance = aes_key.encrypt(0);

    // Create proof data for Pubkey Validity
    let proof_data =
        PubkeyValidityData::new(&elgamal_keypair).map_err(|_| TokenError::ProofGeneration)?;

    // The proof is included in the same transaction of a corresponding token-2022 instruction
    // Appends the proof instruction right after the `ConfigureAccount` instruction.
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    // Configure account with the proof
    let configure_account_instruction = configure_account(
        &spl_token_2022::id(),
        &recipient_associated_token_address,
        &mint.pubkey(),
        decryptable_balance,
        maximum_pending_balance_credit_counter,
        &wallet_2.pubkey(),
        &[],
        proof_location,
    )
    .unwrap();

    let mut instructions = vec![
        create_associated_token_account_instruction,
        reallocate_instruction,
    ];
    instructions.extend(configure_account_instruction);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_2.pubkey()),
        &[&wallet_2],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Recipient Token Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );
    Ok(())
}
