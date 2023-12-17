// solana-test-validator --bpf-program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb ~/code/misc/solana-program-library/target/deploy/spl_token_2022.so
use solana_client::{
    nonblocking::rpc_client::RpcClient as NonBlockingRpcClient, rpc_client::RpcClient,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    signature::{Keypair, Signer},
    system_instruction::create_account,
    transaction::Transaction,
};
use spl_token_2022::{
    error::TokenError,
    extension::{
        confidential_transfer::{
            account_info::{ApplyPendingBalanceAccountInfo, TransferAccountInfo},
            instruction::{
                apply_pending_balance, configure_account, deposit, transfer_with_split_proofs,
                PubkeyValidityData, TransferSplitContextStateAccounts,
            },
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, ExtensionType,
    },
    instruction::{initialize_account, initialize_mint, mint_to},
    proof::ProofLocation,
    solana_zk_token_sdk::{
        encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
        instruction::ciphertext_commitment_equality::CiphertextCommitmentEqualityProofContext,
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
    token::{ExtensionInitializationParams, Token},
};
use std::{error::Error, mem::size_of, sync::Arc};

mod utils;
use utils::get_or_create_keypair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Create Wallets -------------------------------------------------------

    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let wallet_2 = get_or_create_keypair("wallet_2")?;

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    client.request_airdrop(&wallet_1.pubkey(), 5 * LAMPORTS_PER_SOL)?;
    client.request_airdrop(&wallet_2.pubkey(), 5 * LAMPORTS_PER_SOL)?;

    // 2. Create Mint ----------------------------------------------------------

    let mint = Keypair::new();
    let mint_authority = &wallet_1;
    let freeze_authority = &wallet_1;
    let decimals = 2;

    // Confidential Transfer Extension authority
    let authority = &wallet_1;
    // Auditor ElGamal pubkey
    let auditor_elgamal_keypair = ElGamalKeypair::new_rand();

    let extension_initialization_params =
        vec![ExtensionInitializationParams::ConfidentialTransferMint {
            authority: Some(authority.pubkey()),
            auto_approve_new_accounts: true,
            auditor_elgamal_pubkey: Some((*auditor_elgamal_keypair.pubkey()).into()),
        }];

    let space = ExtensionType::try_calculate_account_len::<Mint>(
        &extension_initialization_params
            .iter()
            .map(|e| e.extension())
            .collect::<Vec<_>>(),
    )?;

    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Create the instructions to create the mint account
    let create_account_instruction = create_account(
        &wallet_1.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    // Instructions for extensions (if multiple extensions are used)
    let mut extension_instructions = Vec::new();
    for params in extension_initialization_params {
        let instr = params.instruction(&spl_token_2022::id(), &mint.pubkey())?;
        extension_instructions.push(instr);
    }

    // Initialize the mint account
    let initialize_mint_instruction = initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &mint_authority.pubkey(),
        Some(&freeze_authority.pubkey()),
        decimals,
    )?;

    // Create vector of instructions
    let mut instructions = vec![create_account_instruction];
    instructions.extend(extension_instructions);
    instructions.push(initialize_mint_instruction);

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

    // 3. Create and Configure Token Account -----------------------------------

    let token_account = Keypair::new();
    let extensions = vec![ExtensionType::ConfidentialTransferAccount];
    let space = ExtensionType::try_calculate_account_len::<Account>(&extensions)?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Create the instructions to create the token account
    let create_account_instruction = create_account(
        &wallet_1.pubkey(),
        &token_account.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    // Initialize the token account
    let initialize_account_instruction = initialize_account(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        &wallet_1.pubkey(),
    )?;

    // Create the ElGamal keypair and AES key for the token account
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();
    let aes_key = AeKey::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();

    // TODO: what is this?
    let maximum_pending_balance_credit_counter = 65536;
    let decryptable_balance = aes_key.encrypt(0);

    // Create proof data for Pubkey Validity
    let proof_data =
        PubkeyValidityData::new(&elgamal_keypair).map_err(|_| TokenError::ProofGeneration)?;

    // The proof is included in the same transaction of a corresponding token-2022 instruction
    // Appends the proof instruction right after the `ConfigureAccount` instruction.
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    // Instructions to configure the token account, including the proof instruction
    let configure_account_instruction = configure_account(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        decryptable_balance,
        maximum_pending_balance_credit_counter,
        &wallet_1.pubkey(),
        &[],
        proof_location,
    )
    .unwrap();

    // Create vector of instructions
    let mut instructions = vec![create_account_instruction, initialize_account_instruction];
    instructions.extend(configure_account_instruction);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &token_account],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Token Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // 4. Mint Tokens ----------------------------------------------------------

    let amount = 100_000_00;

    let mint_to_instruction: Instruction = mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &token_account.pubkey(),
        &wallet_1.pubkey(),
        &[&wallet_1.pubkey()],
        amount,
    )?;

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

    // 5. Deposit Tokens -------------------------------------------------------

    let deposit_amount = 10_000_00; // Amount to deposit

    let deposit_instruction = deposit(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        deposit_amount,
        decimals,
        &wallet_1.pubkey(),
        &[&wallet_1.pubkey()],
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

    // 6. Apply Pending Balance -------------------------------------------------
    // Apply pending balance for token account, seems like it must be done in a separate transaction

    // Create a new client
    let rpc_client = NonBlockingRpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // Create a program client
    let program_client =
        ProgramRpcClient::new(Arc::new(rpc_client), ProgramRpcClientSendTransaction);

    // Create a token client, to use helper functions
    let token = Token::new(
        Arc::new(program_client),
        &spl_token_2022::id(),
        &mint.pubkey(),
        Some(decimals),
        Arc::new(wallet_1.insecure_clone()),
    );

    // Retrieve token account information.
    let account = token.get_account_info(&token_account.pubkey()).await?;

    // Unpack a portion of the TLV data as the desired type
    let confidential_transfer_account = account.get_extension::<ConfidentialTransferAccount>()?;

    // Create the `ApplyPendingBalance` instruction account information from `ConfidentialTransferAccount`.
    let account_info = ApplyPendingBalanceAccountInfo::new(confidential_transfer_account);

    // Return the pending balance credit counter of the account
    let expected_pending_balance_credit_counter = account_info.pending_balance_credit_counter();

    // Update the decryptable available balance
    let new_decryptable_available_balance = account_info
        .new_decryptable_available_balance(&elgamal_keypair.secret(), &aes_key)
        .map_err(|_| TokenError::AccountDecryption)?;

    // Create a `ApplyPendingBalance` instruction
    let apply_pending_balance_instruction = apply_pending_balance(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        expected_pending_balance_credit_counter,
        new_decryptable_available_balance,
        &wallet_1.pubkey(),
        &[&wallet_1.pubkey()],
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[apply_pending_balance_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nApply Pending Balance: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // 7. Create Another Token Account -----------------------------------------

    let token_account_2 = Keypair::new();
    let extensions = vec![ExtensionType::ConfidentialTransferAccount];
    let space = ExtensionType::try_calculate_account_len::<Account>(&extensions)?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let create_account_instruction = create_account(
        &wallet_2.pubkey(),
        &token_account_2.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    let initialize_account_instruction = initialize_account(
        &spl_token_2022::id(),
        &token_account_2.pubkey(),
        &mint.pubkey(),
        &wallet_2.pubkey(),
    )?;

    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_2, &token_account_2.pubkey().to_bytes()).unwrap();
    let aes_key = AeKey::new_from_signer(&wallet_2, &token_account_2.pubkey().to_bytes()).unwrap();

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
        &token_account_2.pubkey(),
        &mint.pubkey(),
        decryptable_balance,
        maximum_pending_balance_credit_counter,
        &wallet_2.pubkey(),
        &[],
        proof_location,
    )
    .unwrap();

    let mut instructions = vec![create_account_instruction, initialize_account_instruction];
    instructions.extend(configure_account_instruction);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_2.pubkey()),
        &[&wallet_2, &token_account_2],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Another Token Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // 8. Prepare proof data ---------------------------------------------------

    // Must first create 3 accounts to store proofs before transferring tokens

    let context_state_authority = &wallet_1;

    let equality_proof_context_state_account = Keypair::new();
    let equality_proof_pubkey = equality_proof_context_state_account.pubkey();

    let ciphertext_validity_proof_context_state_account = Keypair::new();
    let ciphertext_validity_proof_pubkey = ciphertext_validity_proof_context_state_account.pubkey();

    let range_proof_context_state_account = Keypair::new();
    let range_proof_pubkey = range_proof_context_state_account.pubkey();

    let transfer_context_state_accounts = TransferSplitContextStateAccounts {
        equality_proof: &equality_proof_pubkey,
        ciphertext_validity_proof: &ciphertext_validity_proof_pubkey,
        range_proof: &range_proof_pubkey,
        authority: &context_state_authority.pubkey(),
        no_op_on_uninitialized_split_context_state: false,
        close_split_context_state_accounts: None,
    };

    // Sender token account
    let state = token
        .get_account_info(&token_account.pubkey())
        .await
        .unwrap();
    let extension = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let transfer_account_info = TransferAccountInfo::new(extension);

    let transfer_balance = 1;

    let sender_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();
    let sender_aes_key =
        AeKey::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();

    let recipient_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_2, &token_account_2.pubkey().to_bytes()).unwrap();

    // Generate proof data
    let (
        equality_proof_data,
        ciphertext_validity_proof_data,
        range_proof_data,
        source_decrypt_handles,
    ) = transfer_account_info
        .generate_split_transfer_proof_data(
            transfer_balance,
            &sender_elgamal_keypair,
            &sender_aes_key,
            &recipient_elgamal_keypair.pubkey(),
            Some(auditor_elgamal_keypair.pubkey()),
        )
        .unwrap();

    // 9. Create 3 proofs ------------------------------------------------------

    // Range Proof ------------------------------------------------------------------------------

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
    // Separate transaction because proof instruction too large
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
        "\nVerify Range Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
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
        "\nCreate Equality Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Ciphertext Validity Proof ----------------------------------------------------------------

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
        "\nCreate Ciphertext Validity Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // 10. Transfer with Split Proofs -------------------------------------------

    let account = token.get_account_info(&token_account.pubkey()).await?;
    let confidential_transfer_account = account.get_extension::<ConfidentialTransferAccount>()?;
    let account_info = TransferAccountInfo::new(confidential_transfer_account);

    // Calculate the new decryptable available balance
    let new_decryptable_available_balance = account_info
        .new_decryptable_available_balance(transfer_balance, &sender_aes_key)
        .map_err(|_| TokenError::AccountDecryption)?;

    // Create the 'transfer_with_split_proofs' instruction
    let transfer_with_split_proofs_instruction = transfer_with_split_proofs(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        &token_account_2.pubkey(),
        new_decryptable_available_balance.into(),
        &wallet_1.pubkey(),
        transfer_context_state_accounts,
        &source_decrypt_handles,
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

    // 11. Close Proof Accounts --------------------------------------------------

    let context_state_authority_pubkey = context_state_authority.pubkey();
    let sender = &wallet_1.pubkey();

    let close_equality_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &equality_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &sender,
    );

    let close_ciphertext_validity_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &ciphertext_validity_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &sender,
    );

    let close_range_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &range_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &sender,
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
