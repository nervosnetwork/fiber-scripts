use std::vec;

use super::*;
use ckb_std::since::{EpochNumberWithFraction, Since};
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_crypto::secp::Generator,
    ckb_hash::blake2b_256,
    ckb_types::{
        bytes::Bytes, core::TransactionBuilder, core::TransactionView, packed::*, prelude::*,
    },
    context::Context,
};
use musig2::{
    BinaryEncoding, CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices,
};
use secp256k1::{
    PublicKey, Secp256k1, SecretKey,
    rand::{self, RngCore},
};
use sha2::{Digest, Sha256};

const MAX_CYCLES: u64 = 10_000_000;
const BYTE_SHANNONS: u64 = 100_000_000;
const EMPTY_WITNESS_ARGS: [u8; 16] = [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0];

// a helper fn to generate 2-2 multisig keys for testing
fn generate_multisig_keys() -> (SecretKey, SecretKey, KeyAggContext) {
    // generate two random secret keys
    let sec_key_1 = SecretKey::new(&mut rand::thread_rng());
    let sec_key_2 = SecretKey::new(&mut rand::thread_rng());

    // public key aggregation
    let secp256k1 = Secp256k1::new();
    let pubkey_1 = sec_key_1.public_key(&secp256k1);
    let pubkey_2 = sec_key_2.public_key(&secp256k1);
    let key_agg_ctx = KeyAggContext::new(vec![pubkey_1, pubkey_2]).unwrap();

    (sec_key_1, sec_key_2, key_agg_ctx)
}

fn multisig(
    sec_key_1: SecretKey,
    sec_key_2: SecretKey,
    key_agg_ctx: KeyAggContext,
    message: [u8; 32],
) -> Vec<u8> {
    let mut first_round_1 = {
        let mut nonce_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_seed);

        FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            0,
            SecNonceSpices::new()
                .with_seckey(sec_key_1)
                .with_message(&message),
        )
        .unwrap()
    };

    let mut first_round_2 = {
        let mut nonce_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_seed);

        FirstRound::new(
            key_agg_ctx,
            nonce_seed,
            1,
            SecNonceSpices::new()
                .with_seckey(sec_key_2)
                .with_message(&message),
        )
        .unwrap()
    };

    first_round_1
        .receive_nonce(1, first_round_2.our_public_nonce())
        .unwrap();
    first_round_2
        .receive_nonce(0, first_round_1.our_public_nonce())
        .unwrap();

    let mut second_round_1 = first_round_1.finalize(sec_key_1, &message).unwrap();
    let mut second_round_2 = first_round_2.finalize(sec_key_2, &message).unwrap();
    let signature_1: PartialSignature = second_round_1.our_signature();
    let signature_2: PartialSignature = second_round_2.our_signature();

    second_round_1.receive_signature(1, signature_2).unwrap();
    let aggregated_signature_1: CompactSignature = second_round_1.finalize().unwrap();
    second_round_2.receive_signature(0, signature_1).unwrap();
    let aggregated_signature_2: CompactSignature = second_round_2.finalize().unwrap();

    assert_eq!(aggregated_signature_1, aggregated_signature_2);

    aggregated_signature_1.to_bytes().to_vec()
}

/// Compute the message of a transaction
/// We prefer computing the message this way rather than using the transaction hash.
/// This ensures the signature remains valid even if the script code is updated.
fn compute_tx_message(tx: &TransactionView) -> [u8; 32] {
    let tx = tx
        .data()
        .raw()
        .as_builder()
        .cell_deps(Default::default())
        .build();
    blake2b_256(tx.as_slice())
}

#[test]
fn test_funding_lock() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let funding_lock_bin = loader.load_binary("funding-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let funding_lock_out_point = context.deploy_cell(funding_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);

    // generate two random secret keys
    let (sec_key_1, sec_key_2, key_agg_ctx) = generate_multisig_keys();

    // prepare scripts
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let lock_script = context
        .build_script(&funding_lock_out_point, pubkey_hash[0..20].to_vec().into())
        .expect("script");

    // prepare cell deps
    let funding_lock_dep = CellDep::new_builder()
        .out_point(funding_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let cell_deps = vec![funding_lock_dep, auth_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let output_lock = Script::new_builder()
        .args(Bytes::from("output_lock").pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(output_lock.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(output_lock)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign and add witness
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = multisig(sec_key_1, sec_key_2, key_agg_ctx, message);

    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        x_only_pubkey.to_vec(),
        signature,
    ]
    .concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();

    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_commitment_lock_no_pending_htlcs() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // prepare script
    let (sec_key_1, sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 42 hours
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let settlement_script = [
        [0].to_vec(),
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let always_success_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();
    let cell_deps = vec![commitment_lock_dep, auth_dep, always_success_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount) as u64).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // build transaction with revocation unlock logic
    let to_revocation_lock = Script::new_builder()
        .args(Bytes::from("to_local_output").pack())
        .build();
    let to_revocation_output = CellOutput::new_builder()
        .capacity(((local_amount + remote_amount) as u64).pack())
        .lock(to_revocation_lock)
        .build();
    let to_revocation_output_data = Bytes::from("to_revocation_output_data").pack();

    let outputs = vec![to_revocation_output.clone()];
    let outputs_data = vec![to_revocation_output_data.clone()];
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    let commitment_tx_new_version = 100u64;

    // sign and add witness
    let message = blake2b_256(
        [
            to_revocation_output.as_slice(),
            to_revocation_output_data.as_slice(),
            &args[0..28],
            commitment_tx_new_version.to_be_bytes().as_slice(),
        ]
        .concat(),
    );

    let signature = multisig(sec_key_1, sec_key_2, key_agg_ctx.clone(), message);
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        commitment_tx_new_version.to_be_bytes().to_vec(),
        x_only_pubkey.to_vec(),
        signature,
    ]
    .concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();
    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // test with settlement unlock logic (local settlement key)
    let new_settlement_script = [
        [0].to_vec(),
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        [0u8; 36].to_vec(),
    ]
    .concat();

    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();

    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((remote_amount as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_settlement_key
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_settlement_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        vec![0xFF, 0x00], // unlock with local settlement key, no preimage
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // test with settlement unlock logic (remote settlement key)
    let input_out_point = context.create_cell(outputs[0].clone(), Bytes::new());

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(delay_epoch.as_u64().pack())
        .build();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity((remote_amount as u64).pack())
            .lock(Script::new_builder().build())
            .build(),
    ];
    let outputs_data = [Bytes::new()];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_settlement_key
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_settlement_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        new_settlement_script.clone(),
        vec![0xFE, 0x00], // unlock with remote settlement key, no preimage
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_commitment_lock_with_two_pending_htlcs() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 10.5 epoch =~ 42 hours
    let half_delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(5, 0, 1), false); // 5 epoch
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let remote_htlc_key2 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let local_htlc_key2 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let preimage2 = [24u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS as u128;
    let payment_amount2 = 8 * BYTE_SHANNONS as u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();
    // timeout after 2024-04-02 01:00:00
    let expiry2 = Since::from_timestamp(1712062800, true).unwrap();

    let pending_htlcs = [
        [2].to_vec(),
        [0b00000000].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
        [0b00000011].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        Sha256::digest(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");
    let always_success_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let always_success_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();
    let cell_deps = vec![commitment_lock_dep, auth_dep, always_success_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(
                ((local_amount + remote_amount + payment_amount1 + payment_amount2) as u64).pack(),
            )
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let delay_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .lock(always_success_script)
            .build(),
        Bytes::new(),
    );

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let new_pending_htlcs = [
        [1].to_vec(),
        [0b00000011].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        Sha256::digest(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with remote_htlc_key1 and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // sign with remote_htlc_pubkey and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with remote_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // build transaction with local_htlc_pubkey unlock offered pending htlc 1
    let since = Since::from_timestamp(1711976400 + 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let delay_epoch_input = CellInput::new_builder()
        .previous_output(delay_input_out_point.clone())
        .since(since.as_u64().pack())
        .build();
    let inputs = vec![input, delay_epoch_input.clone()];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with local_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with local_htlc_pubkey and none-expired since should fail
    let since = Since::from_timestamp(1711976400 - 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![
        input,
        delay_epoch_input
            .clone()
            .as_builder()
            .since(since.as_u64().pack())
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with local_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("none-expired since should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#11")); // InvalidExpiry

    // build transaction with remote_htlc_pubkey2 unlock received pending htlc 2
    let since = Since::from_timestamp(1712062800 + 1000, true).unwrap();
    let input = CellInput::new_builder()
        .since(delay_epoch.as_u64().pack())
        .previous_output(input_out_point.clone())
        .build();
    let inputs = vec![
        input,
        delay_epoch_input
            .clone()
            .as_builder()
            .since(since.as_u64().pack())
            .build(),
    ];

    let new_pending_htlcs = [
        [1].to_vec(),
        [0b00000000].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();
    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();

    println!("new_settlement_script: {:x?}", new_settlement_script);
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_pubkey2
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x00].to_vec(), // unlock with remote_htlc_pubkey2 and no preimage
        signature.clone(),
    ]
    .concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();
    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with local_htlc_pubkey2 unlock received pending htlc 2
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(half_delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_key2
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x01].to_vec(), // unlock with local_htlc_key2 and preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with local_htlc_key2 and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x01].to_vec(), // unlock with local_htlc_key2 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // sign with local_htlc_key2 and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x00].to_vec(), // unlock with local_htlc_key2 and no preimage
        signature,
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // test with settlement unlock logic (remote settlement key)
    let new_two_party_settlement = [
        [0u8; 36].to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let new_settlement_script = [pending_htlcs.clone(), new_two_party_settlement.clone()].concat();
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();

    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(
                ((local_amount + 5 * BYTE_SHANNONS as u128 + 8 * BYTE_SHANNONS as u128) as u64)
                    .pack(),
            )
            .lock(new_lock_script.clone())
            .build(),
    ];

    let outputs_data = [Bytes::new()];
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_settlement_key
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_settlement_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        vec![0xFE, 0x00], // unlock with remote settlement key,
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // test with batch unlock logic (remote settlement key + remote htlc key1)
    let new_pending_htlcs = [
        [1].to_vec(),
        [0b00000011].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        Sha256::digest(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let new_two_party_settlement = [
        [0u8; 36].to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let new_settlement_script = [new_pending_htlcs.clone(), new_two_party_settlement].concat();
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();

    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();
    // sign with remote_settlement_key and remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature1 = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();

    let signature2 = remote_settlement_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();

    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x02],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature1.clone(),
        preimage1.to_vec(),
        [0xFE, 0x00].to_vec(), // unlock with remote settlement
        signature2.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_commitment_lock_with_two_pending_htlcs_and_sudt() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let simple_udt_bin = loader.load_binary("../../deps/simple_udt");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);
    let simple_udt_out_point = context.deploy_cell(simple_udt_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 42 hours
    let half_delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(5, 0, 1), false); // 5 epoch
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = 22222222222222222222u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = 11111111111111111111u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let remote_htlc_key2 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let local_htlc_key2 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let preimage2 = [24u8; 32];
    let payment_amount1 = 1234567890u128;
    let payment_amount2 = 9876543210u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();
    // timeout after 2024-04-02 01:00:00
    let expiry2 = Since::from_timestamp(1712062800, true).unwrap();

    let pending_htlcs = [
        [2].to_vec(),
        [0b00000000].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
        [0b00000001].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        blake2b_256(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let two_party_settlement = [
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");
    let always_success_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .expect("script");
    let type_script = context
        .build_script(&simple_udt_out_point, vec![42; 32].into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let always_success_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();
    let simple_udt_dep = CellDep::new_builder()
        .out_point(simple_udt_out_point)
        .build();
    let cell_deps = vec![
        commitment_lock_dep,
        auth_dep,
        always_success_dep,
        simple_udt_dep,
    ]
    .pack();

    // prepare cells
    let total_sudt_amount = local_amount + remote_amount + payment_amount1 + payment_amount2;
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        total_sudt_amount.to_le_bytes().to_vec().into(),
    );
    let delay_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .lock(always_success_script)
            .build(),
        Bytes::new(),
    );

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(half_delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let new_pending_htlcs = [
        [1].to_vec(),
        [0b00000001].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        blake2b_256(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();
    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(new_lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
    ];
    let outputs_data: Vec<Bytes> = vec![
        (total_sudt_amount - payment_amount1)
            .to_le_bytes()
            .to_vec()
            .into(),
    ];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with remote_htlc_key1 and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let err = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    assert!(err.to_string().contains("#22")); // PreimageError

    // sign with remote_htlc_key1 and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with remote_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let err = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    assert!(err.to_string().contains("#22")); // PreimageError

    // build transaction with local_htlc_pubkey unlock offered pending htlc 1
    let since = Since::from_timestamp(1711976400 + 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let delay_epoch_input = CellInput::new_builder()
        .previous_output(delay_input_out_point.clone())
        .since(since.as_u64().pack())
        .build();
    let inputs = vec![input, delay_epoch_input.clone()];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with local_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with remote_htlc_pubkey2 unlock received pending htlc 2
    let since = Since::from_timestamp(1712062800 + 1000, true).unwrap();
    let input = CellInput::new_builder()
        .since(delay_epoch.as_u64().pack())
        .previous_output(input_out_point.clone())
        .build();
    let inputs = vec![
        input,
        delay_epoch_input
            .clone()
            .as_builder()
            .since(since.as_u64().pack())
            .build(),
    ];
    let new_pending_htlcs = [
        [1].to_vec(),
        [0b00000000].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();
    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    let new_lock_script = lock_script.as_builder().args(new_args.pack()).build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(new_lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
    ];
    let outputs_data: Vec<Bytes> = vec![
        (total_sudt_amount - payment_amount2)
            .to_le_bytes()
            .to_vec()
            .into(),
    ];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key2
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x00].to_vec(), // unlock with remote_htlc_key2 and no preimage
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with local_htlc_pubkey2 unlock received pending htlc 2
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(half_delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_key2
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x01].to_vec(), // unlock with local_htlc_key2 and preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with local_htlc_key2 and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x01].to_vec(), // unlock with local_htlc_key2 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let err = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    assert!(err.to_string().contains("#22")); // PreimageError

    // sign with local_htlc_key2 and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x00].to_vec(), // unlock with local_htlc_key2 and no preimage
        signature,
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let err = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    assert!(err.to_string().contains("#22")); // PreimageError
}

// v1 HTLC entry layout: 1 (htlc_type) + 16 (payment_amount) + 32 (payment_hash)
// + 20 (remote_htlc_pubkey_hash) + 20 (local_htlc_pubkey_hash) + 8 (htlc_expiry) = 97
fn build_htlc_entry_v1(
    htlc_type: u8,
    payment_amount: u128,
    payment_hash: &[u8],
    remote_key_hash: &[u8],
    local_key_hash: &[u8],
    expiry_since: u64,
) -> Vec<u8> {
    let mut vec = Vec::new();
    vec.push(htlc_type);
    vec.extend_from_slice(&payment_amount.to_le_bytes());
    vec.extend_from_slice(payment_hash);
    vec.extend_from_slice(remote_key_hash);
    vec.extend_from_slice(local_key_hash);
    vec.extend_from_slice(&expiry_since.to_le_bytes());
    assert_eq!(vec.len(), 97);
    vec
}

#[test]
fn v1_settlement_with_preimage_unlock_succeeds() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 10.5 epoch =~ 42 hours
    let half_delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(5, 0, 1), false); // 5 epoch
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let remote_htlc_key2 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let local_htlc_key2 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let preimage2 = [24u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS as u128;
    let payment_amount2 = 8 * BYTE_SHANNONS as u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();
    // timeout after 2024-04-02 01:00:00
    let expiry2 = Since::from_timestamp(1712062800, true).unwrap();

    let htlc1_entry = build_htlc_entry_v1(
        0b00000000,
        payment_amount1,
        &blake2b_256(preimage1),
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key1.1.serialize())[0..20],
        expiry1.as_u64(),
    );
    let htlc2_entry = build_htlc_entry_v1(
        0b00000011,
        payment_amount2,
        &Sha256::digest(preimage2),
        &blake2b_256(remote_htlc_key2.1.serialize())[0..20],
        &blake2b_256(local_htlc_key2.1.serialize())[0..20],
        expiry2.as_u64(),
    );

    let pending_htlcs = [[2].to_vec(), htlc1_entry.clone(), htlc2_entry.clone()].concat();

    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    // v1: args gain one byte (57 -> 58), [57] = feature bitmap, bit0 = ONCHAIN_FULL_PAYMENT_HASH
    args.push(0x01);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");
    let always_success_script = context
        .build_script(&always_success_out_point, Bytes::new())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let always_success_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();
    let cell_deps = vec![commitment_lock_dep, auth_dep, always_success_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(
                ((local_amount + remote_amount + payment_amount1 + payment_amount2) as u64).pack(),
            )
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let delay_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .lock(always_success_script)
            .build(),
        Bytes::new(),
    );

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let new_pending_htlcs = [[1].to_vec(), htlc2_entry.clone()].concat();

    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();
    let mut new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    // propagate the v1 features byte into the derived cell args
    new_args.push(0x01);
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with remote_htlc_key1 and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // sign with remote_htlc_pubkey and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with remote_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // build transaction with local_htlc_pubkey unlock offered pending htlc 1
    let since = Since::from_timestamp(1711976400 + 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let delay_epoch_input = CellInput::new_builder()
        .previous_output(delay_input_out_point.clone())
        .since(since.as_u64().pack())
        .build();
    let inputs = vec![input, delay_epoch_input.clone()];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with local_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with local_htlc_pubkey and none-expired since should fail
    let since = Since::from_timestamp(1711976400 - 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![
        input,
        delay_epoch_input
            .clone()
            .as_builder()
            .since(since.as_u64().pack())
            .build(),
    ];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x00].to_vec(), // unlock with local_htlc_key1 and no preimage
        signature.clone(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("none-expired since should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#11")); // InvalidExpiry

    // build transaction with remote_htlc_pubkey2 unlock received pending htlc 2
    let since = Since::from_timestamp(1712062800 + 1000, true).unwrap();
    let input = CellInput::new_builder()
        .since(delay_epoch.as_u64().pack())
        .previous_output(input_out_point.clone())
        .build();
    let inputs = vec![
        input,
        delay_epoch_input
            .clone()
            .as_builder()
            .since(since.as_u64().pack())
            .build(),
    ];

    let new_pending_htlcs = [[1].to_vec(), htlc1_entry.clone()].concat();
    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let mut new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    // propagate the v1 features byte into the derived cell args
    new_args.push(0x01);
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_pubkey2
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x00].to_vec(), // unlock with remote_htlc_pubkey2 and no preimage
        signature.clone(),
    ]
    .concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with local_htlc_pubkey2 unlock received pending htlc 2
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(half_delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_key2
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x01].to_vec(), // unlock with local_htlc_key2 and preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with local_htlc_key2 and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x01].to_vec(), // unlock with local_htlc_key2 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // sign with local_htlc_key2 and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x01, 0x00].to_vec(), // unlock with local_htlc_key2 and no preimage
        signature,
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError

    // test with settlement unlock logic (remote settlement key)
    let new_two_party_settlement = [
        [0u8; 36].to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let new_settlement_script = [pending_htlcs.clone(), new_two_party_settlement.clone()].concat();
    let mut new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    // propagate the v1 features byte into the derived cell args
    new_args.push(0x01);

    let mut new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(
                ((local_amount + 5 * BYTE_SHANNONS as u128 + 8 * BYTE_SHANNONS as u128) as u64)
                    .pack(),
            )
            .lock(new_lock_script.clone())
            .build(),
    ];

    let outputs_data = [Bytes::new()];
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_settlement_key
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_settlement_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        vec![0xFE, 0x00], // unlock with remote settlement key,
        signature.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // test with batch unlock logic (remote settlement key + remote htlc key1)
    let new_two_party_settlement = [
        [0u8; 36].to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let new_pending_htlcs = [[1].to_vec(), htlc2_entry.clone()].concat();
    let new_settlement_script = [new_pending_htlcs.clone(), new_two_party_settlement].concat();
    let mut new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    // propagate the v1 features byte into the derived cell args
    new_args.push(0x01);

    new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();

    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();
    // sign with remote_settlement_key and remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature1 = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();

    let signature2 = remote_settlement_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();

    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x02],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature1.clone(),
        preimage1.to_vec(),
        [0xFE, 0x00].to_vec(), // unlock with remote settlement
        signature2.clone(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

// v1 regression test for the prefix-truncation attack: the committed on-chain
// hash contains the 20-byte prefix of hash(preimage) plus 12 junk bytes; the
// legacy contract would accept, the v1 contract must reject with PreimageError

#[test]
fn v1_settlement_rejects_prefix_only_preimage() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);
    let _always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 10.5 epoch =~ 42 hours
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS as u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();

    // committed hash: valid 20-byte prefix of hash(preimage1) followed by 12
    // attacker-controlled bytes
    let mut committed_payment_hash = blake2b_256(preimage1)[0..20].to_vec();
    committed_payment_hash.extend_from_slice(&[0xAA; 12]);

    let htlc1_entry = build_htlc_entry_v1(
        0b00000000,
        payment_amount1,
        &committed_payment_hash,
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key1.1.serialize())[0..20],
        expiry1.as_u64(),
    );

    let pending_htlcs = [[1].to_vec(), htlc1_entry.clone()].concat();

    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    args.push(0x01);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let always_success_dep = CellDep::new_builder()
        .out_point(context.deploy_cell(ALWAYS_SUCCESS.clone()))
        .build();
    let cell_deps = vec![commitment_lock_dep, auth_dep, always_success_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let new_settlement_script = [[0].to_vec(), two_party_settlement.clone()].concat();
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1 and the correct preimage must still fail,
    // because the committed hash is not the full hash of the preimage
    let message: [u8; 32] = compute_tx_message(&tx);

    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock with remote_htlc_key1 and preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("prefix-only payment hash should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError
}

// v1 feature bitmap with unknown bit1 set must be rejected with ArgsLenError
#[test]
fn v1_args_with_unknown_flag_bits_rejected() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let commitment_tx_version = 42u64;

    let settlement_script = [[0x00u8; 97].to_vec(), [0x00u8; 72].to_vec()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    // unknown feature bit1 set
    args.push(0x03);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let cell_deps = vec![commitment_lock_dep, auth_dep].pack();

    // prepare cells and transaction
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity((1000u64).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1000u64).pack())
            .lock(Script::new_builder().build())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witness(
            [
                EMPTY_WITNESS_ARGS.to_vec(),
                vec![0x01],
                settlement_script.clone(),
                [0x00, 0x00].to_vec(),
                [0u8; 65].to_vec(),
            ]
            .concat()
            .pack(),
        )
        .build();

    // run
    let error = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("unknown feature bits should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#12")); // ArgsLenError
}

// 58-byte args with a zero feature bitmap must NOT fall through to the legacy
// layout; they must be rejected with ArgsLenError
#[test]
fn v1_zero_mask_rejected() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let commitment_tx_version = 42u64;

    let settlement_script = [[0x00u8; 97].to_vec(), [0x00u8; 72].to_vec()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    // zero feature bitmap on 58 bytes is explicitly invalid
    args.push(0x00);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let cell_deps = vec![commitment_lock_dep, auth_dep].pack();

    // prepare cells and transaction
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity((1000u64).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1000u64).pack())
            .lock(Script::new_builder().build())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .witness(
            [
                EMPTY_WITNESS_ARGS.to_vec(),
                vec![0x01],
                settlement_script.clone(),
                [0x00, 0x00].to_vec(),
                [0u8; 65].to_vec(),
            ]
            .concat()
            .pack(),
        )
        .build();

    // run
    let error = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect_err("zero feature mask should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#12")); // ArgsLenError
}

// The args claiming v1 (flag byte at [57]) while the witness and the
// committed snapshot hash use legacy 85-byte HTLC entries: the parser derives
// the witness lengths from the v1 layout, so the snapshot hash check runs over
// a longer slice than the committed script bytes and must reject with
// WitnessHashError.
#[test]
fn v1_settlement_rejects_legacy_htlc_entries() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS as u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();

    // legacy 85-byte HTLC entry committed at commitment time
    let legacy_htlc_entry = [
        [0b00000000].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let pending_htlcs = [[1].to_vec(), legacy_htlc_entry.clone()].concat();
    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    // the fingerprint hash at [36..56] does not cover this flag byte, so the
    // commitment is otherwise a valid legacy one; the args now claim v1
    args.push(0x01);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let cell_deps = vec![commitment_lock_dep, auth_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(delay_epoch.as_u64().pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount) as u64).pack())
            .lock(Script::new_builder().build())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .inputs(vec![input])
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock offered htlc1 with preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("legacy witness entries with v1 args should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#15")); // WitnessHashError
}

// The args staying legacy (57 bytes, committed snapshot hash over
// legacy-summed 85-byte entries) while the witness carries v1 97-byte HTLC
// entries: the legacy arithmetic hashes a different slice than committed and
// must reject with WitnessHashError.
#[test]
fn legacy_settlement_rejects_v1_htlc_entries() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS as u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();

    // v1 97-byte HTLC entry placed in the witness
    let v1_htlc_entry = build_htlc_entry_v1(
        0b00000000,
        payment_amount1,
        &blake2b_256(preimage1),
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key1.1.serialize())[0..20],
        expiry1.as_u64(),
    );
    // the legacy-summed (85-byte) version of the same HTLC committed in args
    let legacy_htlc_entry = [
        [0b00000000].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let legacy_pending_htlcs = [[1].to_vec(), legacy_htlc_entry.clone()].concat();
    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();
    let legacy_settlement_script = [legacy_pending_htlcs, two_party_settlement.clone()].concat();

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&legacy_settlement_script)[0..20],
        &[0x00],
    ]
    .concat();

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let cell_deps = vec![commitment_lock_dep, auth_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount1) as u64).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(delay_epoch.as_u64().pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount) as u64).pack())
            .lock(Script::new_builder().build())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .inputs(vec![input])
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        [[1].to_vec(), v1_htlc_entry, two_party_settlement].concat(),
        [0x00, 0x01].to_vec(), // unlock offered htlc1 with preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("v1 witness entries with legacy args should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#15")); // WitnessHashError
}

// A v1 partial settlement must not brick the derived commitment cell: the
// follow-up cell must keep 58-byte args with the features byte appended at
// [57], so a second settlement tx can still unlock the remaining HTLC through
// the full 32-byte-hash preimage path.
#[test]
fn v1_derived_cell_resettlement_succeeds() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 10.5 epoch =~ 42 hours
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = (400 * BYTE_SHANNONS) as u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = (600 * BYTE_SHANNONS) as u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let local_htlc_key2 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let preimage2 = [24u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS as u128;
    let payment_amount2 = 8 * BYTE_SHANNONS as u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();
    // timeout after 2024-04-02 01:00:00
    let expiry2 = Since::from_timestamp(1712062800, true).unwrap();

    // htlc1: offered, blake2b full hash; htlc2: received, sha256 full hash
    let htlc1_entry = build_htlc_entry_v1(
        0b00000000,
        payment_amount1,
        &blake2b_256(preimage1),
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key2.1.serialize())[0..20],
        expiry1.as_u64(),
    );
    let htlc2_entry = build_htlc_entry_v1(
        0b00000011,
        payment_amount2,
        &Sha256::digest(preimage2),
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key2.1.serialize())[0..20],
        expiry2.as_u64(),
    );

    let pending_htlcs = [[2].to_vec(), htlc1_entry.clone(), htlc2_entry.clone()].concat();

    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    // v1: args gain one byte (57 -> 58), [57] = feature bitmap
    args.push(0x01);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let cell_deps = vec![commitment_lock_dep, auth_dep].pack();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(
                ((local_amount + remote_amount + payment_amount1 + payment_amount2) as u64).pack(),
            )
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // first settlement tx: unlock offered htlc1 via preimage, leaving htlc2
    // pending in the derived commitment cell
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let new_pending_htlcs = [[1].to_vec(), htlc2_entry.clone()].concat();
    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();
    let mut new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01], // subsequent commitment cell
    ]
    .concat();
    // the v1 features byte must be propagated into the derived cell's args
    new_args.push(0x01);
    assert_eq!(new_args.len(), 58);
    assert_eq!(new_args[57], 0x01);

    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock offered htlc1 with preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("partial settlement should pass verification");
    println!("consume cycles: {}", cycles);

    // second settlement tx: unlock the remaining received htlc2 from the
    // v1-derived commitment cell through the full-hash preimage path
    let derived_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount + payment_amount2) as u64).pack())
            .lock(new_lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(derived_input_out_point)
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let final_settlement_script = [[0].to_vec(), two_party_settlement.clone()].concat();
    let mut final_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&final_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    final_args.push(0x01);
    let final_lock_script = lock_script
        .clone()
        .as_builder()
        .args(final_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(((local_amount + remote_amount) as u64).pack())
            .lock(final_lock_script)
            .build(),
    ];
    let outputs_data = [Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_key2 (received htlc preimage path uses the local key)
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        new_settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock received htlc2 with preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("resettlement of the v1-derived cell should pass verification");
    println!("consume cycles: {}", cycles);

    // wrong preimage must still be rejected on the v1-derived cell
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        new_settlement_script,
        [0x00, 0x01].to_vec(),
        signature,
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError
}

// The "xUDT variant" of the v1 re-settlement flow: a v1 partial settlement of
// a UDT commitment cell must keep the features byte in the derived cell's
// args, so the remaining pending HTLC can be settled through the full-hash
// preimage path with the xUDT amount checks applied.
#[test]
fn v1_sudt_derived_cell_resettlement_succeeds() {
    // deploy contract
    let mut context = Context::default();
    let loader = Loader::default();
    let commitment_lock_bin = loader.load_binary("commitment-lock");
    let auth_bin = loader.load_binary("../../deps/auth");
    let simple_udt_bin = loader.load_binary("../../deps/simple_udt");
    let commitment_lock_out_point = context.deploy_cell(commitment_lock_bin);
    let auth_out_point = context.deploy_cell(auth_bin);
    let simple_udt_out_point = context.deploy_cell(simple_udt_bin);

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let half_delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(5, 0, 1), false);
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
    let remote_settlement_key = generator.gen_keypair();
    let remote_amount = 22222222222222222222u128;
    let local_settlement_key = generator.gen_keypair();
    let local_amount = 11111111111111111111u128;

    let remote_htlc_key1 = generator.gen_keypair();
    let local_htlc_key2 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let preimage2 = [24u8; 32];
    let payment_amount1 = 1234567890u128;
    let payment_amount2 = 9876543210u128;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();
    // timeout after 2024-04-02 01:00:00
    let expiry2 = Since::from_timestamp(1712062800, true).unwrap();

    // htlc1: offered, blake2b full hash; htlc2: received, sha256 full hash
    let htlc1_entry = build_htlc_entry_v1(
        0b00000000,
        payment_amount1,
        &blake2b_256(preimage1),
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key2.1.serialize())[0..20],
        expiry1.as_u64(),
    );
    let htlc2_entry = build_htlc_entry_v1(
        0b00000011,
        payment_amount2,
        &Sha256::digest(preimage2),
        &blake2b_256(remote_htlc_key1.1.serialize())[0..20],
        &blake2b_256(local_htlc_key2.1.serialize())[0..20],
        expiry2.as_u64(),
    );

    let pending_htlcs = [[2].to_vec(), htlc1_entry, htlc2_entry.clone()].concat();

    let two_party_settlement = [
        blake2b_256(remote_settlement_key.1.serialize())[0..20].to_vec(),
        remote_amount.to_le_bytes().to_vec(),
        blake2b_256(local_settlement_key.1.serialize())[0..20].to_vec(),
        local_amount.to_le_bytes().to_vec(),
    ]
    .concat();

    let settlement_script = [pending_htlcs.clone(), two_party_settlement.clone()].concat();

    let mut args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&settlement_script)[0..20],
        &[0x00],
    ]
    .concat();
    // v1: args gain one byte (57 -> 58), [57] = feature bitmap
    args.push(0x01);

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.clone().into())
        .expect("script");
    let type_script = context
        .build_script(&simple_udt_out_point, vec![42; 32].into())
        .expect("script");

    // prepare cell deps
    let commitment_lock_dep = CellDep::new_builder()
        .out_point(commitment_lock_out_point)
        .build();
    let auth_dep = CellDep::new_builder().out_point(auth_out_point).build();
    let simple_udt_dep = CellDep::new_builder()
        .out_point(simple_udt_out_point)
        .build();
    let cell_deps = vec![commitment_lock_dep, auth_dep, simple_udt_dep].pack();

    // prepare cells
    let total_sudt_amount = local_amount + remote_amount + payment_amount1 + payment_amount2;
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        total_sudt_amount.to_le_bytes().to_vec().into(),
    );

    // first settlement tx: unlock offered htlc1 via preimage, leaving htlc2
    // pending in the derived commitment cell
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(half_delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let new_pending_htlcs = [[1].to_vec(), htlc2_entry.clone()].concat();
    let new_settlement_script = [new_pending_htlcs.clone(), two_party_settlement.clone()].concat();
    let mut new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_settlement_script)[0..20],
        &[0x01], // subsequent commitment cell
    ]
    .concat();
    // the v1 features byte must be propagated into the derived cell's args
    new_args.push(0x01);
    assert_eq!(new_args.len(), 58);
    assert_eq!(new_args[57], 0x01);

    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(new_lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
    ];
    let outputs_data: Vec<Bytes> = vec![
        (total_sudt_amount - payment_amount1)
            .to_le_bytes()
            .to_vec()
            .into(),
    ];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_key1
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock offered htlc1 with preimage
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("partial settlement of the v1 UDT cell should pass verification");
    println!("consume cycles: {}", cycles);

    // second settlement tx: unlock the remaining received htlc2 from the
    // v1-derived UDT commitment cell through the full-hash preimage path
    let derived_input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(new_lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        (total_sudt_amount - payment_amount1)
            .to_le_bytes()
            .to_vec()
            .into(),
    );
    let input = CellInput::new_builder()
        .previous_output(derived_input_out_point)
        .since(delay_epoch.as_u64().pack())
        .build();
    let inputs = vec![input];

    let final_settlement_script = [[0].to_vec(), two_party_settlement.clone()].concat();
    let mut final_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&final_settlement_script)[0..20],
        &[0x01],
    ]
    .concat();
    final_args.push(0x01);
    let final_lock_script = lock_script
        .clone()
        .as_builder()
        .args(final_args.pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(final_lock_script)
            .type_(Some(type_script.clone()).pack())
            .build(),
    ];
    let outputs_data: Vec<Bytes> = vec![
        (total_sudt_amount - payment_amount1 - payment_amount2)
            .to_le_bytes()
            .to_vec()
            .into(),
    ];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_key2 (received htlc preimage path uses the local key)
    let message: [u8; 32] = compute_tx_message(&tx);
    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        new_settlement_script.clone(),
        [0x00, 0x01].to_vec(), // unlock received htlc2 with preimage
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("resettlement of the v1-derived UDT cell should pass verification");
    println!("consume cycles: {}", cycles);

    // wrong preimage must still be rejected on the v1-derived UDT cell
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        new_settlement_script,
        [0x00, 0x01].to_vec(),
        signature,
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);
    assert!(error.to_string().contains("#22")); // PreimageError
}
