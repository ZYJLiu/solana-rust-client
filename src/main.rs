// solana-test-validator --bpf-program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb /Users/johnliu/code/misc/solana-program-library/target/deploy/spl_token_2022.so
use futures::try_join;
use solana_client::{
    nonblocking::rpc_client::RpcClient as NonBlockingRpcClient, rpc_client::RpcClient,
};
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    instruction::Instruction,
    instruction::InstructionError,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Signer,
    signer::keypair::Keypair,
    system_instruction,
    transaction::{Transaction, TransactionError},
    transport::TransportError,
};
use spl_token_2022::{
    error::TokenError,
    extension::{
        confidential_transfer::{
            self,
            account_info::{
                ApplyPendingBalanceAccountInfo, TransferAccountInfo, WithdrawAccountInfo,
            },
            instruction::{
                CloseSplitContextStateAccounts, TransferSplitContextStateAccounts,
                TransferWithFeeSplitContextStateAccounts,
            },
            ConfidentialTransferAccount, ConfidentialTransferMint, MAXIMUM_DEPOSIT_TRANSFER_AMOUNT,
        },
        BaseStateWithExtensions, ExtensionType, StateWithExtensionsOwned,
    },
    instruction,
    proof::ProofLocation,
    solana_zk_token_sdk::{
        encryption::{auth_encryption::*, elgamal::*},
        zk_token_elgamal::pod::{self, Zeroable},
        zk_token_proof_instruction::*,
        zk_token_proof_program,
        zk_token_proof_state::ProofContextState,
    },
    state::{Account, Mint},
};
use spl_token_client::{
    client::{
        ProgramRpcClient, ProgramRpcClientSendTransaction, RpcClientResponse, SendTransaction,
        SimulateTransaction,
    },
    proof_generation::transfer_with_fee_split_proof_data,
    token::{self, ExtensionInitializationParams, Token, TokenError as TokenClientError},
};
use std::{error::Error, mem::size_of, sync::Arc};
mod utils;
use utils::{get_or_create_keypair, print_transaction_link};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let wallet_2 = get_or_create_keypair("wallet_2")?;

    let client = RpcClient::new_with_commitment(
        "http://127.0.0.1:8899",
        CommitmentConfig {
            commitment: CommitmentLevel::Confirmed,
        },
    );

    // Request airdrop for the wallet_1
    client.request_airdrop(&wallet_1.pubkey(), 1_000_000_000 * 5)?;
    client.request_airdrop(&wallet_2.pubkey(), 1_000_000_000 * 5)?;

    let mint = Keypair::new();
    let mint_authority = &wallet_1;
    let freeze_authority = &wallet_1;
    let decimals = 2;

    let authority = &wallet_1;
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

    let create_account_instruction = system_instruction::create_account(
        &wallet_1.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    let mut extension_instructions = Vec::new();
    for params in extension_initialization_params {
        let instr = params.instruction(&spl_token_2022::id(), &mint.pubkey())?;
        extension_instructions.push(instr);
    }

    let initialize_mint_instruction = instruction::initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &mint_authority.pubkey(),
        Some(&freeze_authority.pubkey()),
        decimals,
    )?;

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

    // ----------------------------------------------------------

    let token_account = Keypair::new();
    let extensions = vec![ExtensionType::ConfidentialTransferAccount];
    let space = ExtensionType::try_calculate_account_len::<Account>(&extensions)?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let create_account_instruction = system_instruction::create_account(
        &wallet_1.pubkey(),
        &token_account.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    let initialize_account_instruction = instruction::initialize_account(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        &wallet_1.pubkey(),
    )?;

    let instructions = vec![create_account_instruction, initialize_account_instruction];

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

    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();
    let aes_key = AeKey::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();

    let maximum_pending_balance_credit_counter = 65536; // Default value or custom
    let decryptable_balance = aes_key.encrypt(0);

    // Create proof data for Pubkey Validity
    let proof_data = confidential_transfer::instruction::PubkeyValidityData::new(&elgamal_keypair)
        .map_err(|_| TokenError::ProofGeneration)?;

    // The proof is included in the same transaction of a corresponding token-2022 instruction
    // Appends the proof instruction right after the `ConfigureAccount` instruction.
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    let configure_account_instruction = confidential_transfer::instruction::configure_account(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        decryptable_balance,
        maximum_pending_balance_credit_counter,
        &wallet_1.pubkey(),
        &[],
        proof_location, // Proof location (None in this case)
    )
    .unwrap();

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &configure_account_instruction,
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nConfigure Token Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // ----------------------------------------------------------

    let amount = 100_000_00;

    let mint_to_instruction: Instruction = spl_token_2022::instruction::mint_to(
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

    // ----------------------------------------------------------

    let deposit_amount = 10_000_00; // Amount to deposit

    let deposit_instruction = confidential_transfer::instruction::deposit(
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

    // ----------------------------------------------------------

    let rpc_client = NonBlockingRpcClient::new_with_commitment(
        std::string::String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    let program_client =
        ProgramRpcClient::new(Arc::new(rpc_client), ProgramRpcClientSendTransaction);

    // Set this up to use helper functions
    let token_client = Token::new(
        Arc::new(program_client),
        &spl_token_2022::id(),
        &mint.pubkey(),
        Some(decimals),
        Arc::new(wallet_1.insecure_clone()),
    );

    // Retrieve token account information.
    let account = token_client
        .get_account_info(&token_account.pubkey())
        .await?;

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
    let apply_pending_balance_instruction =
        confidential_transfer::instruction::apply_pending_balance(
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

    // ----------------------------------------------------------

    let withdraw_amount = 123;

    // Retrieve account information
    let account = token_client
        .get_account_info(&token_account.pubkey())
        .await?;

    //  Unpack a portion of the TLV data as the desired type
    let confidential_transfer_account = account.get_extension::<ConfidentialTransferAccount>()?;
    // Create the `WithdrawAccount` instruction account information from `ConfidentialTransferAccount`.
    let account_info = WithdrawAccountInfo::new(confidential_transfer_account);

    // Create a withdraw proof data
    let proof_data = account_info
        .generate_proof_data(withdraw_amount, &elgamal_keypair, &aes_key)
        .map_err(|_| TokenError::ProofGeneration)?;

    // Keypair for the context state account (account that stores proof data)
    let context_state_keypair = Keypair::new();
    let context_state_pubkey = context_state_keypair.pubkey();
    let context_state_authority = &wallet_1;

    let instruction_type = ProofInstruction::VerifyWithdraw;
    let space = std::mem::size_of::<ProofContextState<WithdrawProofContext>>();
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Pubkeys associated with a context state account to be used as parameters to functions
    let withdraw_proof_context_state_info = ContextStateInfo {
        context_state_account: &context_state_pubkey,
        context_state_authority: &context_state_authority.pubkey(),
    };

    // Create context state account with space for proof data owned by zk-token-proof-program
    let create_context_state_instruction = system_instruction::create_account(
        &wallet_1.pubkey(),
        &context_state_pubkey,
        rent,
        space as u64,
        &zk_token_proof_program::id(),
    );

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_context_state_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &context_state_keypair],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Context Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Create a proof instruction with proof data to initialize the context state account
    let initialize_context_state_instruction =
        [instruction_type
            .encode_verify_proof(Some(withdraw_proof_context_state_info), &proof_data)];

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &initialize_context_state_instruction,
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nInitialize Context Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // A proof location type meant to be used for arguments to instruction constructors.
    // The proof is pre-verified into a context state account.
    let proof_location = ProofLocation::ContextStateAccount(&context_state_pubkey);

    // Update the decryptable available balance
    let new_decryptable_available_balance = account_info
        .new_decryptable_available_balance(withdraw_amount, &aes_key)
        .map_err(|_| TokenError::AccountDecryption)?;

    // let balance = new_decryptable_available_balance.decrypt(&aes_key);
    // print!("\nAvailable Balance: {:?}", balance);

    // Create a `Withdraw` instruction
    let withdraw_instruction = confidential_transfer::instruction::withdraw(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        withdraw_amount,
        decimals,
        new_decryptable_available_balance,
        &wallet_1.pubkey(),
        &[&wallet_1.pubkey()],
        proof_location,
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &withdraw_instruction,
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nWithdraw Tokens: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // ----------------------------------------------------------

    // Create and Configure a new token account for wallet_2
    let token_account_2 = Keypair::new();
    let extensions = vec![ExtensionType::ConfidentialTransferAccount];
    let space = ExtensionType::try_calculate_account_len::<Account>(&extensions)?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let create_account_instruction = system_instruction::create_account(
        &wallet_2.pubkey(),
        &token_account_2.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    let initialize_account_instruction = instruction::initialize_account(
        &spl_token_2022::id(),
        &token_account_2.pubkey(),
        &mint.pubkey(),
        &wallet_2.pubkey(),
    )?;

    let instructions = vec![create_account_instruction, initialize_account_instruction];

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&wallet_2.pubkey()),
        &[&wallet_2, &token_account_2],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Token Account 2: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_2, &token_account_2.pubkey().to_bytes()).unwrap();
    let aes_key = AeKey::new_from_signer(&wallet_2, &token_account_2.pubkey().to_bytes()).unwrap();

    let maximum_pending_balance_credit_counter = 65536; // Default value or custom
    let decryptable_balance = aes_key.encrypt(0);

    // Create proof data for Pubkey Validity
    let proof_data = confidential_transfer::instruction::PubkeyValidityData::new(&elgamal_keypair)
        .map_err(|_| TokenError::ProofGeneration)?;

    // The proof is included in the same transaction of a corresponding token-2022 instruction
    // Appends the proof instruction right after the `ConfigureAccount` instruction.
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    let configure_account_instruction = confidential_transfer::instruction::configure_account(
        &spl_token_2022::id(),
        &token_account_2.pubkey(),
        &mint.pubkey(),
        decryptable_balance,
        maximum_pending_balance_credit_counter,
        &wallet_2.pubkey(),
        &[],
        proof_location, // Proof location (None in this case)
    )
    .unwrap();

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &configure_account_instruction,
        Some(&wallet_2.pubkey()),
        &[&wallet_2],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nConfigure Token Account 2: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // ----------------------------------------------------------

    // let mint_info = token_client.get_mint_info().await?;
    // let auditor_elgamal_pubkey = mint_info.get_extension::<ConfidentialTransferMint>()?;

    // let recipient_token_info = token_client
    //     .get_account_info(&token_account_2.pubkey())
    //     .await?;

    // let recipient_elgamal_pubkey = recipient_token_info
    //     .get_extension::<ConfidentialTransferAccount>()?
    //     .elgamal_pubkey;

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
    let state = token_client
        .get_account_info(&token_account.pubkey())
        .await
        .unwrap();
    let extension = state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap();
    let transfer_account_info = TransferAccountInfo::new(extension);

    let transfer_balance = 1000;

    let sender_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();
    let sender_aes_key =
        AeKey::new_from_signer(&wallet_1, &token_account.pubkey().to_bytes()).unwrap();

    let recipient_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_2, &token_account_2.pubkey().to_bytes()).unwrap();

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

    let results = try_join!(
        token_client.create_range_proof_context_state_for_transfer(
            transfer_context_state_accounts,
            &range_proof_data,
            &range_proof_context_state_account,
        ),
        token_client.create_equality_proof_context_state_for_transfer(
            transfer_context_state_accounts,
            &equality_proof_data,
            &equality_proof_context_state_account,
        ),
        token_client.create_ciphertext_validity_proof_context_state_for_transfer(
            transfer_context_state_accounts,
            &ciphertext_validity_proof_data,
            &ciphertext_validity_proof_context_state_account,
        )
    )?;
    let (result1, result2, result3) = results;
    print_transaction_link(result1, "Create equality proof account");
    print_transaction_link(result2, "Create ciphertext validity proof account");
    print_transaction_link(result3, "Create for range proof account");

    let signer = Arc::new(wallet_1.insecure_clone()) as Arc<dyn Signer>;
    let signers = vec![signer];
    let transfer_result = token_client
        .confidential_transfer_transfer_with_split_proofs(
            &token_account.pubkey(),   // sender token account
            &token_account_2.pubkey(), // recipient token account
            &wallet_1.pubkey(),        // sender
            transfer_context_state_accounts,
            transfer_balance,
            Some(transfer_account_info),
            &sender_aes_key,
            &source_decrypt_handles,
            &signers,
        )
        .await?;

    print_transaction_link(transfer_result, "Transfer Tokens");

    // close context state accounts
    let context_state_authority_pubkey = context_state_authority.pubkey();
    let sender = &wallet_1.pubkey();
    let close_context_state_signers = &[context_state_authority];

    let results = try_join!(
        token_client.confidential_transfer_close_context_state(
            &equality_proof_pubkey,
            sender,
            &context_state_authority_pubkey,
            close_context_state_signers,
        ),
        token_client.confidential_transfer_close_context_state(
            &ciphertext_validity_proof_pubkey,
            sender,
            &context_state_authority_pubkey,
            close_context_state_signers,
        ),
        token_client.confidential_transfer_close_context_state(
            &range_proof_pubkey,
            sender,
            &context_state_authority_pubkey,
            close_context_state_signers,
        ),
    )?;

    let (result1, result2, result3) = results;
    print_transaction_link(result1, "Close equality proof account");
    print_transaction_link(result2, "Close ciphertext validity proof account");
    print_transaction_link(result3, "Close for range proof account");

    // token_client
    //     .process_ixs(
    //         &[system_instruction::create_account(
    //             &wallet_1.pubkey(),
    //             &context_state_pubkey,
    //             rent,
    //             space as u64,
    //             &zk_token_proof_program::id(),
    //         )],
    //         &[&context_state_authority, &context_state_keypair],
    //     )
    //     .await?;

    // token_client
    //     .process_ixs(
    //         &[instruction_type
    //             .encode_verify_proof(Some(withdraw_proof_context_state_info), &proof_data)],
    //         &[] as &[&dyn Signer; 0],
    //     )
    //     .await?;

    Ok(())
}
