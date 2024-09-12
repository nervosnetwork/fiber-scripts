use std::vec;

use super::*;
use ckb_std::since::{EpochNumberWithFraction, Since};
use ckb_testtool::{
    ckb_crypto::secp::Generator,
    ckb_hash::blake2b_256,
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};
use musig2::{
    BinaryEncoding, CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices,
};
use secp256k1::{
    rand::{self, RngCore},
    PublicKey, Secp256k1, SecretKey,
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
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();
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

    // prepare script
    let (sec_key_1, sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 42 hours
    let commitment_tx_version = 42u64;

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
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
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // build transaction with revocation unlock logic
    let to_revocation_lock = Script::new_builder()
        .args(Bytes::from("to_local_output").pack())
        .build();
    let to_revocation_output = CellOutput::new_builder()
        .capacity(1000u64.pack())
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
        vec![0xFF],
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

    // build transaction with non-pending HTLC unlock logic
    let to_local_output_script = Script::new_builder()
        .args(Bytes::from("to_local_output").pack())
        .build();
    let to_local_output = CellOutput::new_builder()
        .capacity(500u64.pack())
        .lock(to_local_output_script)
        .build();
    let to_local_output_data = Bytes::from("to_local_output_data").pack();
    let to_remote_output_script = Script::new_builder()
        .args(Bytes::from("to_remote_output").pack())
        .build();
    let to_remote_output = CellOutput::new_builder()
        .capacity(500u64.pack())
        .lock(to_remote_output_script)
        .build();
    let to_remote_output_data = Bytes::from("to_remote_output_data").pack();

    let outputs = vec![to_local_output.clone(), to_remote_output.clone()];
    let outputs_data = vec![to_local_output_data.clone(), to_remote_output_data.clone()];

    let since = Since::from_epoch(EpochNumberWithFraction::new(12, 0, 1), false); // 48 hours
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .since(since.as_u64().pack())
        .build();

    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign and add witness
    let message = blake2b_256(
        [
            to_local_output.as_slice(),
            to_local_output_data.as_slice(),
            to_remote_output.as_slice(),
            to_remote_output_data.as_slice(),
            &args,
        ]
        .concat(),
    );

    let signature = multisig(sec_key_1, sec_key_2, key_agg_ctx, message);
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0xFE],
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
fn test_commitment_lock_with_two_pending_htlcs() {
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
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 42 hours
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
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

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&pending_htlcs)[0..20],
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
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

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

    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_pending_htlcs)[0..20],
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS - payment_amount1 as u64).pack())
        .lock(new_lock_script.clone())
        .build()];
    let outputs_data = vec![Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with remote_htlc_pubkey and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
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

    // sign with remote_htlc_pubkey and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
        signature,
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // run
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    println!("error: {}", error);

    // build transaction with local_htlc_pubkey unlock offered pending htlc 1
    let since = Since::from_timestamp(1711976400 + 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(since.as_u64().pack())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS).pack())
        .lock(new_lock_script.clone())
        .build()];
    let outputs_data = vec![Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
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
        .since(since.as_u64().pack())
        .build();
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
        signature,
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("none-expired since should fail");
    println!("error: {}", error);

    // build transaction with remote_htlc_pubkey unlock received pending htlc 2
    let since = Since::from_timestamp(1712062800 + 1000, true).unwrap();
    let input = CellInput::new_builder()
        .since(since.as_u64().pack())
        .previous_output(input_out_point.clone())
        .build();

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
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(new_pending_htlcs)[0..20],
    ]
    .concat();
    let new_lock_script = lock_script.as_builder().args(new_args.pack()).build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS - payment_amount2 as u64).pack())
        .lock(new_lock_script.clone())
        .build()];
    let outputs_data = vec![Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = remote_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        pending_htlcs.clone(),
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

    // // build transaction with local_htlc_pubkey unlock received pending htlc 2
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS).pack())
        .lock(new_lock_script.clone())
        .build()];
    let outputs_data = vec![Bytes::new()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        pending_htlcs.clone(),
        signature.clone(),
        preimage2.to_vec(),
    ]
    .concat();

    let success_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let cycles = context
        .verify_tx(&success_tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // sign with local_htlc_pubkey and wrong preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        pending_htlcs.clone(),
        signature.clone(),
        preimage1.to_vec(),
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("wrong preimage should fail");
    println!("error: {}", error);

    // sign with local_htlc_pubkey and empty preimage should fail
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        pending_htlcs.clone(),
        signature,
    ]
    .concat();

    let fail_tx = tx.as_advanced_builder().witness(witness.pack()).build();
    let error = context
        .verify_tx(&fail_tx, MAX_CYCLES)
        .expect_err("empty preimage should fail");
    println!("error: {}", error);
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

    // prepare script
    let (_sec_key_1, _sec_key_2, key_agg_ctx) = generate_multisig_keys();
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pubkey = aggregated_pubkey.x_only_public_key().0.serialize();
    let pubkey_hash = blake2b_256(x_only_pubkey);
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false); // 42 hours
    let commitment_tx_version = 42u64;

    let mut generator = Generator::new();
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

    let args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&pending_htlcs)[0..20],
    ]
    .concat();

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
    let total_sudt_amount = 424242424242424242u128;
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity((1000 * BYTE_SHANNONS).pack())
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build(),
        total_sudt_amount.to_le_bytes().to_vec().into(),
    );

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

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
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_pending_htlcs)[0..20],
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(new_args.pack())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS).pack())
        .lock(new_lock_script.clone())
        .type_(Some(type_script.clone()).pack())
        .build()];
    let outputs_data: Vec<Bytes> = vec![(total_sudt_amount - payment_amount1)
        .to_le_bytes()
        .to_vec()
        .into()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = remote_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
        signature,
        preimage1.to_vec(),
    ]
    .concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();
    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with local_htlc_pubkey unlock offered pending htlc 1
    let since = Since::from_timestamp(1711976400 + 1000, true).unwrap();

    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .since(since.as_u64().pack())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS).pack())
        .lock(new_lock_script.clone())
        .type_(Some(type_script.clone()).pack())
        .build()];
    let outputs_data: Vec<Bytes> = vec![total_sudt_amount.to_le_bytes().to_vec().into()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_htlc_key1
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x00],
        pending_htlcs.clone(),
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

    // build transaction with remote_htlc_pubkey unlock received pending htlc 2
    let since = Since::from_timestamp(1712062800 + 1000, true).unwrap();
    let input = CellInput::new_builder()
        .since(since.as_u64().pack())
        .previous_output(input_out_point.clone())
        .build();

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
    let new_args = [
        &pubkey_hash[0..20],
        delay_epoch.as_u64().to_le_bytes().as_slice(),
        commitment_tx_version.to_be_bytes().as_slice(),
        &blake2b_256(&new_pending_htlcs)[0..20],
    ]
    .concat();
    let new_lock_script = lock_script.as_builder().args(new_args.pack()).build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS).pack())
        .lock(new_lock_script.clone())
        .type_(Some(type_script.clone()).pack())
        .build()];
    let outputs_data: Vec<Bytes> = vec![(total_sudt_amount - payment_amount2)
        .to_le_bytes()
        .to_vec()
        .into()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with remote_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = remote_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        pending_htlcs.clone(),
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

    // // build transaction with local_htlc_pubkey unlock received pending htlc 2
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS).pack())
        .lock(new_lock_script.clone())
        .type_(Some(type_script.clone()).pack())
        .build()];
    let outputs_data: Vec<Bytes> = vec![total_sudt_amount.to_le_bytes().to_vec().into()];
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps)
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .build();

    // sign with local_htlc_pubkey
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_htlc_key2
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [
        EMPTY_WITNESS_ARGS.to_vec(),
        vec![0x01],
        pending_htlcs,
        signature,
        preimage2.to_vec(),
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
