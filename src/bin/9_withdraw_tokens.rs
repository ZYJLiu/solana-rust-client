// cargo run --bin 9_withdraw_tokens
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
            account_info::WithdrawAccountInfo, instruction::withdraw, ConfidentialTransferAccount,
        },
        BaseStateWithExtensions,
    },
    proof::ProofLocation,
    solana_zk_token_sdk::{
        encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
        zk_token_proof_instruction::{ContextStateInfo, ProofInstruction, WithdrawProofContext},
        zk_token_proof_program,
        zk_token_proof_state::ProofContextState,
    },
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::Token,
};
use std::{error::Error, sync::Arc};

use keypair_utils::get_or_create_keypair;

// The "withdraw" instruction is used to convert the "available" confidential balance back to the non-confidential balance of the token account.
// This requires creating a "withdraw proof" account
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let wallet_1 = get_or_create_keypair("wallet_1")?;
    let mint = get_or_create_keypair("mint")?;
    let decimals = 2;

    // Associated token address of the sender
    let sender_associated_token_address = get_associated_token_address_with_program_id(
        &wallet_1.pubkey(), // Token account owner
        &mint.pubkey(),     // Mint
        &spl_token_2022::id(),
    );

    let client = RpcClient::new_with_commitment(
        String::from("http://127.0.0.1:8899"),
        CommitmentConfig::confirmed(),
    );

    // A "non-blocking" RPC client (for async calls)
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

    // Amount to withdraw, 10.00 tokens
    let withdraw_amount = 10_00;

    // Get sender token account data
    let token_account = token
        .get_account_info(&sender_associated_token_address)
        .await?;

    // Unpack the ConfidentialTransferAccount extension portion of the token account data
    let extension_data = token_account.get_extension::<ConfidentialTransferAccount>()?;

    // Confidential Transfer extension data needed to construct a `Withdraw` instruction (available balance,)
    let withdraw_account_info = WithdrawAccountInfo::new(extension_data);

    // Derive the ElGamal keypair and AES key for the sender token account
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes())
            .unwrap();
    let aes_key =
        AeKey::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes()).unwrap();

    // Create a withdraw proof data
    let proof_data =
        withdraw_account_info.generate_proof_data(withdraw_amount, &elgamal_keypair, &aes_key)?;

    // Generate address for withdraw proof account
    let withdraw_proof_context_state_account = Keypair::new();
    let withdraw_proof_pubkey = withdraw_proof_context_state_account.pubkey();
    // Authority for the withdraw proof account (to close the account)
    let context_state_authority = &wallet_1;

    let space = std::mem::size_of::<ProofContextState<WithdrawProofContext>>();
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let withdraw_proof_context_state_info = ContextStateInfo {
        context_state_account: &withdraw_proof_pubkey,
        context_state_authority: &context_state_authority.pubkey(),
    };

    // Instruction to create the withdraw proof account
    let create_withdraw_proof_account = create_account(
        &wallet_1.pubkey(),
        &withdraw_proof_pubkey,
        rent,
        space as u64,
        &zk_token_proof_program::id(),
    );

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_withdraw_proof_account],
        Some(&wallet_1.pubkey()),
        &[&wallet_1, &withdraw_proof_context_state_account],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Withdraw Proof Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Instruction to initialize account with proof data
    // Sent as separate transaction because proof instruction too large
    let verify_withdraw_proof_instruction = ProofInstruction::VerifyWithdraw
        .encode_verify_proof(Some(withdraw_proof_context_state_info), &proof_data);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[verify_withdraw_proof_instruction],
        Some(&wallet_1.pubkey()),
        &[&wallet_1],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nInitialize Withdraw Proof Account: https://solana.fm/tx/{}?cluster=localnet-solana",
        transaction_signature
    );

    // Update the decryptable available balance
    let new_decryptable_available_balance =
        withdraw_account_info.new_decryptable_available_balance(withdraw_amount, &aes_key)?;

    // Print the available balance before and after the withdraw
    let prebalance = withdraw_account_info
        .available_balance
        .decrypt(&elgamal_keypair.secret());

    let postbalance = new_decryptable_available_balance.decrypt(&aes_key);

    print!("\nAvailable Balance Before: {:?}", prebalance);
    print!("\nAvailable Balance After: {:?}", postbalance);

    // The proof is pre-verified into a context state account.
    let proof_location = ProofLocation::ContextStateAccount(&withdraw_proof_pubkey);

    // Create a `Withdraw` instruction
    let withdraw_instruction = withdraw(
        &spl_token_2022::id(),
        &sender_associated_token_address,
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
    Ok(())
}
