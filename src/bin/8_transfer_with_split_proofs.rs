// cargo run --bin 8_transfer_with_split_proofs
use solana_client::{
    nonblocking::rpc_client::RpcClient as NonBlockingRpcClient, rpc_client::RpcClient,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    signature::{Keypair, Signer},
    system_instruction::create_account,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            account_info::TransferAccountInfo,
            instruction::{transfer_with_split_proofs, TransferSplitContextStateAccounts},
            ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        BaseStateWithExtensions, StateWithExtensionsOwned,
    },
    solana_zk_token_sdk::{
        encryption::{
            auth_encryption::AeKey,
            elgamal::{self, ElGamalKeypair},
        },
        instruction::ciphertext_commitment_equality::CiphertextCommitmentEqualityProofContext,
        zk_token_elgamal::pod::ElGamalPubkey,
        zk_token_proof_instruction::{
            close_context_state, BatchedGroupedCiphertext2HandlesValidityProofContext,
            BatchedRangeProofContext, ContextStateInfo, ProofInstruction,
        },
        zk_token_proof_program,
        zk_token_proof_state::ProofContextState,
    },
    state::{Account, Mint},
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::Token,
};
use std::{error::Error, mem::size_of, sync::Arc};

use keypair_utils::get_or_create_keypair;

// Must first create 3 accounts to store proofs before sending the confidential transfer
// This must be done in a separate transactions because the proofs are too large for single transaction
// (range proof requires two separate transactions because the proof instruction is too large)

// Equality Proof - prove that ciphertexts encrypt the same value
// Ciphertext Validity Proof - prove that ciphertext is properly encrypted with the correct public key (one for the sender, one for the receiver, one for the auditor)
// Range Proof - prove that ciphertexts encrypt a value in a specified range (0, u64::MAX), (positive amount, enough tokens to send)

// 1. Create the 3 proof accounts
// 2. Perform the confidential transfer using the 3 proof accounts
// 3. Close the 3 proof accounts
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let wallet_2 = get_or_create_keypair("wallet_2")?;
    let mint = get_or_create_keypair("mint")?;
    let decimals = 2;

    // Associated token address of the sender
    let sender_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_1.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    // Associated token address of the recipient
    let recipient_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_2.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // A "non-blocking" RPC client (for async calls), used to set up the "token" client
    let rpc_client = NonBlockingRpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    let program_client =
        ProgramRpcClient::new(Arc::new(rpc_client), ProgramRpcClientSendTransaction);

    // Create a "token" client, to use various helper functions for Token Extensions
    let token = Token::new(
        Arc::new(program_client),
        &spl_token_2022::id(),
        &mint.pubkey(),
        Some(decimals),
        Arc::new(wallet_1.insecure_clone()),
    );

    // "Authority" for the proof accounts (to close the accounts after the transfer)
    let context_state_authority = &wallet_1;

    // Generate keypair to use as address for equality proof account
    let equality_proof_context_state_account = Keypair::new();
    let equality_proof_pubkey = equality_proof_context_state_account.pubkey();

    // Generate keypair to use as address for ciphertext validity proof account
    let ciphertext_validity_proof_context_state_account = Keypair::new();
    let ciphertext_validity_proof_pubkey = ciphertext_validity_proof_context_state_account.pubkey();

    // Generate keypair to use as address for range proof account
    let range_proof_context_state_account = Keypair::new();
    let range_proof_pubkey = range_proof_context_state_account.pubkey();

    // Required for transfer_with_split_proofs instruction
    let transfer_context_state_accounts = TransferSplitContextStateAccounts {
        equality_proof: &equality_proof_pubkey,
        ciphertext_validity_proof: &ciphertext_validity_proof_pubkey,
        range_proof: &range_proof_pubkey,
        authority: &context_state_authority.pubkey(),
        no_op_on_uninitialized_split_context_state: false,
        close_split_context_state_accounts: None,
    };

    // Get sender token account data
    let token_account_info = token
        .get_account_info(&sender_associated_token_address)
        .await?;

    // Get the confidential transfer extension data from the token account data
    let extension_data = token_account_info.get_extension::<ConfidentialTransferAccount>()?;

    // confidential transfer extension data needed to create proof data for the transfer (available balance)
    let transfer_account_info = TransferAccountInfo::new(extension_data);

    // 100.00 tokens to transfer
    let transfer_amount = 100_00;

    // Derive the ElGamal keypair and AES key for the sender token account
    let sender_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes())?;
    let sender_aes_key =
        AeKey::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes())?;

    // Get recipient token account data
    let recipient_account = token
        .get_account(recipient_associated_token_address)
        .await?;

    // Get recipient ElGamal pubkey from the recipient token account data and convert to elgamal::ElGamalPubkey
    // Used to encrypt the transfer amount under the recipient ElGamal pubkey
    let recipient_elgamal_pubkey: elgamal::ElGamalPubkey =
        StateWithExtensionsOwned::<Account>::unpack(recipient_account.data)?
            .get_extension::<ConfidentialTransferAccount>()?
            .elgamal_pubkey
            .try_into()?;

    // Get mint account data
    let mint_account = token.get_account(mint.pubkey()).await?;

    // Get auditor ElGamal pubkey from the mint account data
    // Used to encrypt the transfer amount under the auditor ElGamal pubkey
    let auditor_elgamal_pubkey_option = Option::<ElGamalPubkey>::from(
        StateWithExtensionsOwned::<Mint>::unpack(mint_account.data)?
            .get_extension::<ConfidentialTransferMint>()?
            .auditor_elgamal_pubkey,
    );

    // Convert auditor ElGamal pubkey to elgamal::ElGamalPubkey type
    let auditor_elgamal_pubkey: elgamal::ElGamalPubkey = auditor_elgamal_pubkey_option
        .ok_or("No Auditor ElGamal pubkey")?
        .try_into()?;

    // Generate proof data required for proof accounts to use in the transfer instruction
    let (
        equality_proof_data,
        ciphertext_validity_proof_data,
        range_proof_data,
        source_decrypt_handles,
    ) = transfer_account_info
        .generate_split_transfer_proof_data(
            transfer_amount,
            &sender_elgamal_keypair,
            &sender_aes_key,
            &recipient_elgamal_pubkey,
            Some(&auditor_elgamal_pubkey),
        )
        .unwrap();

    // Range Proof ------------------------------------------------------------------------------

    // space and rent required for range proof account
    let space = size_of::<ProofContextState<BatchedRangeProofContext>>();
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Create Account for Range Proof
    let create_range_proof_account_instruction = create_account(
        &wallet_1.pubkey(),
        &range_proof_context_state_account.pubkey(),
        rent,
        space as u64,
        &zk_token_proof_program::id(),
    );

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_range_proof_account_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &range_proof_context_state_account], // Signers
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Range Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Instruction to initialize account with proof data
    // Sent as separate transaction because range proof instruction too large
    let verify_proof_instruction = ProofInstruction::VerifyBatchedRangeProofU128
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: transfer_context_state_accounts.range_proof,
                context_state_authority: transfer_context_state_accounts.authority,
            }),
            &range_proof_data,
        );

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[verify_proof_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nInitialize Range Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Equality Proof ---------------------------------------------------------------------------

    // Calculate the space required for the account
    let space = size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Create Account for Equality Proof
    let create_equality_proof_account_instruction = create_account(
        &wallet_1.pubkey(),
        &transfer_context_state_accounts.equality_proof,
        rent,
        space as u64,
        &zk_token_proof_program::id(),
    );

    // Instruction to initialize account with proof data
    let verify_equality_proof_instruction = ProofInstruction::VerifyCiphertextCommitmentEquality
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: transfer_context_state_accounts.equality_proof,
                context_state_authority: transfer_context_state_accounts.authority,
            }),
            &equality_proof_data,
        );

    let instructions = vec![
        create_equality_proof_account_instruction,
        verify_equality_proof_instruction,
    ];

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &equality_proof_context_state_account], // Signers
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
            "\nCreate and Initialize Equality Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
            transaction_signature
        );

    // Ciphertext Validity Proof ----------------------------------------------------------------

    // Calculate the space required for the account
    let space =
        size_of::<ProofContextState<BatchedGroupedCiphertext2HandlesValidityProofContext>>();
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Create Account for Ciphertext Validity Proof
    let create_ciphertext_validity_proof_account_instruction = create_account(
        &wallet_1.pubkey(),
        &transfer_context_state_accounts.ciphertext_validity_proof,
        rent,
        space as u64,
        &zk_token_proof_program::id(),
    );

    // Instruction to initialize account with proof data
    let verify_ciphertext_validity_proof_instruction =
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity.encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: transfer_context_state_accounts.ciphertext_validity_proof,
                context_state_authority: transfer_context_state_accounts.authority,
            }),
            &ciphertext_validity_proof_data,
        );

    let instructions = vec![
        create_ciphertext_validity_proof_account_instruction,
        verify_ciphertext_validity_proof_instruction,
    ];

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &ciphertext_validity_proof_context_state_account], // Signers
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
            "\nCreate and Initialize Ciphertext Validity Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
            transaction_signature
        );

    // Confidential Transfer with Split Proofs ---------------------------------------------------------------

    // Calculate the new decryptable available balance for the sender token account
    // deducts the transfer amount from the available balance, and recalculates the new decryptable available balance
    let new_decryptable_available_balance = transfer_account_info
        .new_decryptable_available_balance(transfer_amount, &sender_aes_key)?;

    // Create the 'transfer_with_split_proofs' instruction
    let transfer_with_split_proofs_instruction = transfer_with_split_proofs(
        &spl_token_2022::id(),
        &sender_associated_token_address,    // Source token account
        &mint.pubkey(),                      // Mint
        &recipient_associated_token_address, // Destination token account
        new_decryptable_available_balance.into(), // Updated source token account available balance
        &wallet_1.pubkey(),                  // Source token account owner
        transfer_context_state_accounts,     // Proof context state accounts
        &source_decrypt_handles, // The ElGamal ciphertext decryption handle of the transfer amount under the source public key of the transfer.
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[transfer_with_split_proofs_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nConfidential Transfer with Split Proofs: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Close Proof Accounts --------------------------------------------------

    // Authority to close the proof accounts
    let context_state_authority_pubkey = context_state_authority.pubkey();
    // Lamports from the closed proof accounts will be sent to this account
    let destination_account = &wallet_1.pubkey();

    // Close the equality proof account
    let close_equality_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &equality_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &destination_account,
    );

    // Close the ciphertext validity proof account
    let close_ciphertext_validity_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &ciphertext_validity_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &destination_account,
    );

    // Close the range proof account
    let close_range_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &range_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &destination_account,
    );

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[
            close_equality_proof_instruction,
            close_ciphertext_validity_proof_instruction,
            close_range_proof_instruction,
        ],
        Some(&wallet_1.pubkey()),
        &[&wallet_1], // Signers
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nClose Proof Accounts: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );
    Ok(())
}
