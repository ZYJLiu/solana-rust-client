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
    // 1. Setup -------------------------------------------------------

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
    // Authority to modify the `ConfidentialTransferMint` configuration and to
    // approve new accounts (if `auto_approve_new_accounts` is false?)
    let authority = &wallet_1;

    // Auditor ElGamal pubkey
    // Authority to decode any transfer amount in a confidential transfer
    let auditor_elgamal_keypair = ElGamalKeypair::new_rand();

    // Confidential Transfer Mint extensions parameters
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

    // Create the instructions to create the mint account
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

    // 3. Create and Configure Token Account -----------------------------------

    let token_account = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])?;
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

    // The maximum number of `Deposit` and `Transfer` instructions that can
    // credit `pending_balance` before the `ApplyPendingBalance` instruction is executed
    let maximum_pending_balance_credit_counter = 65536;

    // The initial balance is 0
    let decryptable_balance = aes_key.encrypt(0);

    // Create proof data for Pubkey Validity

    // Generating the proof data (client-side)
    // The instruction data that is needed for the `ProofInstruction::VerifyPubkeyValidity` instruction.
    // It includes the cryptographic proof as well as the context data information needed to verify the proof.
    let proof_data =
        PubkeyValidityData::new(&elgamal_keypair).map_err(|_| TokenError::ProofGeneration)?;

    // `InstructionOffset` indicates that proof is included in the same transaction
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    // Instructions to configure the token account, including the proof instruction
    // Appends the `VerifyPubkeyValidityProof` instruction right after the `ConfigureAccount` instruction.
    let configure_account_instruction = configure_account(
        &spl_token_2022::id(),                  // Program ID
        &token_account.pubkey(),                // Token account
        &mint.pubkey(),                         // Mint
        decryptable_balance,                    // Initial balance
        maximum_pending_balance_credit_counter, // Maximum pending balance credit counter
        &wallet_1.pubkey(),                     // Token Account Owner
        &[],                                    // Additional signers
        proof_location,                         // Proof location
    )
    .unwrap();

    // Create vector of instructions
    // Instructions to configure account must come after `initialize_account` instruction
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

    // Confidential balance has separate "pending" and "available" balances
    // Must first deposit tokens from non-confidential balance to "pending" balance

    let deposit_amount = 10_000_00; // Amount to deposit

    // Instruction to deposit from non-confidential balance to "pending" balance
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

    // "pending" balance must be applied to "available" balance before it can be transferred

    // Create a non-blocking RPC client (for async calls)
    let rpc_client = NonBlockingRpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // Create a program client
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

    // Retrieve token account information.
    let account = token.get_account_info(&token_account.pubkey()).await?;

    // Unpack the ConfidentialTransferAccount extension portion of the token account data
    let confidential_transfer_account = account.get_extension::<ConfidentialTransferAccount>()?;

    // ConfidentialTransferAccount extension information needed to construct an `ApplyPendingBalance` instruction.
    let account_info = ApplyPendingBalanceAccountInfo::new(confidential_transfer_account);

    // Return the pending balance credit counter of the account
    let expected_pending_balance_credit_counter = account_info.pending_balance_credit_counter();

    // Update the decryptable available balance (add pending balance to available balance)
    let new_decryptable_available_balance = account_info
        .new_decryptable_available_balance(&elgamal_keypair.secret(), &aes_key)
        .map_err(|_| TokenError::AccountDecryption)?;

    // Create a `ApplyPendingBalance` instruction
    let apply_pending_balance_instruction = apply_pending_balance(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        expected_pending_balance_credit_counter,
        new_decryptable_available_balance, // Cipher text of the new decryptable available balance
        &wallet_1.pubkey(),                // Token account owner
        &[&wallet_1.pubkey()],             // Additional signers
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
    let space = ExtensionType::try_calculate_account_len::<Account>(&[
        ExtensionType::ConfidentialTransferAccount,
    ])?;
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
    // This must be done in a separate transactions because the proofs are too large for single transaction

    // Equality Proof - prove that two ciphertexts encrypt the same value
    // Ciphertext Validity Proof - prove that ciphertexts are properly generated
    // Range Proof - prove that ciphertexts encrypt a value in a specified range (0, u64::MAX)

    // "Authority" for the accounts, to close the accounts after the transfer
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

    let transfer_amount = 1;

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
            transfer_amount,
            &sender_elgamal_keypair,
            &sender_aes_key,
            &recipient_elgamal_keypair.pubkey(),
            Some(auditor_elgamal_keypair.pubkey()),
        )
        .unwrap();

    // 9. Create 3 proofs ------------------------------------------------------

    // Range Proof ------------------------------------------------------------------------------

    // Range proofs are special types of zero-knowledge proof systems
    // that allow users to generate a proof `proof` that a ciphertext `ct` encrypts a
    // value `x` that falls in a specified range `lower_bound`, `upper_bound`

    //   In the confidential extension, we require that a transfer instruction includes
    //   a range proof that certifies the following:

    //   - The proof should certify that there are enough funds in the source account.
    //     Specifically, let `ct_source` be the encrypted balance of a source account
    //     and `ct_transfer` be the encrypted transfer amount. Then we require that
    //     `ct_source - ct_transfer` encrypts a value `x` such that `0 <= x < u64::MAX`.

    //   - The proof should certify that the transfer amount itself is a positive
    //     64 bit number. Let `ct_transfer` be the encrypted amount of a transfer. Then
    //     the proof should certify that `ct_transfer` encrypts a value `x` such that
    //     `0 <= x < u64::MAX`.

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
        "\nInitialize Range Proof Context State: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Equality Proof ---------------------------------------------------------------------------

    //     - _Equality proof_: Recall that a transfer instruction contains two ciphertexts
    //   of the transfer value `x`: a ciphertext under the sender public key
    //   `ct_sender = PKE::encrypt(pk_sender, x)` and one under the receiver public key
    //   `ct_receiver = PKE::encrypt(pk_receiver, x)`. A malicious user can encrypt two
    //   different values for `ct_sender` and `ct_receiver`.

    //   Equality proofs are special types of zero-knowledge proof systems that allow
    //   users to prove that two ciphertexts `ct_0`, `ct_1` encrypt a same value `x`.
    //   In the confidential extension program, we require that a transfer instruction
    //   contains an equality proof that certifies that the two ciphertexts encrypt the
    //   same value.

    //   The zero-knowledge property guarantees that `proof_eq` does not reveal the
    //   actual values of `x_0`, `x_1` but only the fact that `x_0 == x_1`.

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

    // Transfer instruction data must include the transfer amount that is encrypted
    // under the three ElGamal public keys associated with the instruction. To cope
    // with ElGamal decryption as discussed in the previous section, the transfer
    // amount is restricted to 48-bit numbers and is encrypted as two separate
    // numbers: `amount_lo` that represents the low 16-bits and `amount_hi` that
    // represents the high 32-bits.

    // Each `amount_lo` and `amount_hi` is encrypted under the three ElGamal public
    // keys associated with a transfer. Instead of including three independent
    // ciphertexts as part of the transfer data, we use the randomness-reuse property
    // of ElGamal encryption to minimize the size of ciphertexts.

    // In addition to these ciphertexts, transfer data must include proofs that these
    // ciphertexts are generated properly. There are two ways that a user can
    // potentially cheat the program. First a user may provide ciphertexts that are
    // malformed. For example, even if a user may encrypt the transfer amount under a
    // wrong public key, there is no way for the program to check the validity of a
    // ciphertext. Therefore, we require that transfer data require a _ciphertext
    // validity_ proof that certifies that the ciphertexts are properly generated.

    // Ciphertext validity proof only guarantees that a twisted ElGamal ciphertext is
    // properly generated. However, it does not certify any property regarding the
    // encrypted amount in a ciphertext. For example, a malicious user can encrypt
    // negative values, but there is no way for the program to detect this by simply
    // inspecting the ciphertext. Therefore, in addition to a ciphertext validity
    // proof, a transfer instruction must include a _range proof_ that certifies that
    // the encrypted amounts `amount_lo` and `amount_hi` are positive 16 and 32-bit
    // values respectively.

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

    // 10. Transfer with Split Proofs -------------------------------------------

    let account = token.get_account_info(&token_account.pubkey()).await?;
    let confidential_transfer_account = account.get_extension::<ConfidentialTransferAccount>()?;
    let account_info = TransferAccountInfo::new(confidential_transfer_account);

    // Calculate the new decryptable available balance
    let new_decryptable_available_balance = account_info
        .new_decryptable_available_balance(transfer_amount, &sender_aes_key)
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
