use solana_client::{rpc_client::RpcClient, rpc_config::RpcSendTransactionConfig};
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
// use spl_token::state::Mint;
use spl_token_2022::{
    error::TokenError,
    extension::{
        confidential_transfer::{
            self,
            account_info::TransferAccountInfo,
            instruction::{
                CloseSplitContextStateAccounts, TransferSplitContextStateAccounts,
                TransferWithFeeSplitContextStateAccounts,
            },
            ConfidentialTransferAccount, ConfidentialTransferMint, MAXIMUM_DEPOSIT_TRANSFER_AMOUNT,
        },
        BaseStateWithExtensions, ExtensionType,
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
    client::{SendTransaction, SimulateTransaction},
    proof_generation::transfer_with_fee_split_proof_data,
    token::{self, ExtensionInitializationParams, Token, TokenError as TokenClientError},
};
use std::error::Error;

mod utils;
use utils::get_or_create_keypair;

fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let client = RpcClient::new_with_commitment(
        "http://127.0.0.1:8899",
        // "https://api.devnet.solana.com",
        // "https://localnet.helius-rpc.com/?api-key=86e3ed68-c76b-471e-924f-087410e61f05",
        CommitmentConfig {
            commitment: CommitmentLevel::Confirmed,
        },
    );

    // Request airdrop for the wallet_1
    // client.request_airdrop(&wallet_1.pubkey(), 1_000_000_000 * 5)?;

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

    // let recent_blockhash = client.get_latest_blockhash()?;
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

    // let recent_blockhash = client.get_latest_blockhash()?;
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

    let amount = 100_00;

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

    let amount = 1; // Amount to deposit

    // Generate the deposit instruction
    let deposit_instruction = confidential_transfer::instruction::deposit(
        &spl_token_2022::id(),
        &token_account.pubkey(),
        &mint.pubkey(),
        amount,
        decimals,
        &wallet_1.pubkey(),
        &[&wallet_1.pubkey()],
    )?;

    // Create a new transaction for the deposit
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[deposit_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;
    // let transaction_signature = client.send_transaction_with_config(
    //     &transaction,
    //     RpcSendTransactionConfig {
    //         skip_preflight: true,
    //         preflight_commitment: Some(CommitmentLevel::Confirmed),
    //         encoding: None,
    //         max_retries: None,
    //         min_context_slot: None,
    //     },
    // )?;

    println!(
        "\nDeposit Tokens: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    Ok(())
}
