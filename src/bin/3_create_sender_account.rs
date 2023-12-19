// cargo run --bin 3_create_sender_account
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
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let mint = get_or_create_keypair("mint")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // Associated token address of the sender
    let sender_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_1.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Instruction to create associated token account
    let create_associated_token_account_instruction = create_associated_token_account(
        &wallet_1.pubkey(), // Funding account
        &wallet_1.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Instruction to reallocate the token account to include the `ConfidentialTransferAccount` extension
    let reallocate_instruction = reallocate(
        &spl_token_2022::id(),
        &sender_associated_token_address, // Token account
        &wallet_1.pubkey(),               // Payer
        &wallet_1.pubkey(),               // Token account owner
        &[&wallet_1.pubkey()],            // Signers
        &[ExtensionType::ConfidentialTransferAccount], // Extension to reallocate space for
    )?;

    // Create the ElGamal keypair and AES key for the sender token account
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes())
            .unwrap();
    let aes_key =
        AeKey::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes()).unwrap();

    // The maximum number of `Deposit` and `Transfer` instructions that can
    // credit `pending_balance` before the `ApplyPendingBalance` instruction is executed
    let maximum_pending_balance_credit_counter = 65536;

    // Initial token balance is 0
    let decryptable_balance = aes_key.encrypt(0);

    // The instruction data that is needed for the `ProofInstruction::VerifyPubkeyValidity` instruction.
    // It includes the cryptographic proof as well as the context data information needed to verify the proof.
    // Generating the proof data client-side (instead of using a separate proof account)
    let proof_data =
        PubkeyValidityData::new(&elgamal_keypair).map_err(|_| TokenError::ProofGeneration)?;

    // `InstructionOffset` indicates that proof is included in the same transaction
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    // Instructions to configure the token account, including the proof instruction
    // Appends the `VerifyPubkeyValidityProof` instruction right after the `ConfigureAccount` instruction.
    let configure_account_instruction = configure_account(
        &spl_token_2022::id(),                  // Program ID
        &sender_associated_token_address,       // Token account
        &mint.pubkey(),                         // Mint
        decryptable_balance,                    // Initial balance
        maximum_pending_balance_credit_counter, // Maximum pending balance credit counter
        &wallet_1.pubkey(),                     // Token Account Owner
        &[],                                    // Additional signers
        proof_location,                         // Proof location
    )
    .unwrap();

    // Instructions to configure account must come after `initialize_account` instruction
    let mut instructions = vec![
        create_associated_token_account_instruction,
        reallocate_instruction,
    ];
    instructions.extend(configure_account_instruction);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Sender Token Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );
    Ok(())
}
