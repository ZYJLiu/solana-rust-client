// cargo run --bin 6_apply_pending_balance
use std::{error::Error, sync::Arc};

use keypair_utils::get_or_create_keypair;
use solana_client::{
    nonblocking::rpc_client::RpcClient as NonBlockingRpcClient, rpc_client::RpcClient,
};
use solana_sdk::{
    commitment_config::CommitmentConfig, signature::Signer, transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            account_info::ApplyPendingBalanceAccountInfo, instruction::apply_pending_balance,
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions,
    },
    solana_zk_token_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::Token,
};

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

    // Get sender token account data
    let token_account_info = token
        .get_account_info(&sender_associated_token_address)
        .await?;

    // Unpack the ConfidentialTransferAccount extension portion of the token account data
    let confidential_transfer_account =
        token_account_info.get_extension::<ConfidentialTransferAccount>()?;

    // ConfidentialTransferAccount extension information needed to construct an `ApplyPendingBalance` instruction.
    let apply_pending_balance_account_info =
        ApplyPendingBalanceAccountInfo::new(confidential_transfer_account);

    // Return the number of times the pending balance has been credited
    let expected_pending_balance_credit_counter =
        apply_pending_balance_account_info.pending_balance_credit_counter();

    // Create the ElGamal keypair and AES key for the sender token account
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes())
            .unwrap();
    let aes_key =
        AeKey::new_from_signer(&wallet_1, &sender_associated_token_address.to_bytes()).unwrap();

    // Update the decryptable available balance (add pending balance to available balance)
    let new_decryptable_available_balance = apply_pending_balance_account_info
        .new_decryptable_available_balance(&elgamal_keypair.secret(), &aes_key)?;

    // Create a `ApplyPendingBalance` instruction
    let apply_pending_balance_instruction = apply_pending_balance(
        &spl_token_2022::id(),
        &sender_associated_token_address,        // Token account
        expected_pending_balance_credit_counter, // Expected number of times the pending balance has been credited
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
    Ok(())
}
