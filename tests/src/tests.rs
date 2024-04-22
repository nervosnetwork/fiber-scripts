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

const MAX_CYCLES: u64 = 10_000_000;

const BYTE_SHANNONS: u64 = 100_000_000;

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
    let sec_key_1 = SecretKey::new(&mut rand::thread_rng());
    let sec_key_2 = SecretKey::new(&mut rand::thread_rng());

    // public key aggregation
    let secp256k1 = Secp256k1::new();
    let pub_key_1 = sec_key_1.public_key(&secp256k1);
    let pub_key_2 = sec_key_2.public_key(&secp256k1);
    let key_agg_ctx = KeyAggContext::new(vec![pub_key_1, pub_key_2]).unwrap();
    let aggregated_pub_key: PublicKey = key_agg_ctx.aggregated_pubkey();
    let x_only_pub_key = aggregated_pub_key.x_only_public_key().0.serialize();

    // prepare scripts
    let pub_key_hash = blake2b_256(x_only_pub_key);
    let lock_script = context
        .build_script(&funding_lock_out_point, pub_key_hash[0..20].to_vec().into())
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
        .previous_output(input_out_point.clone())
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
    let tx_hash: [u8; 32] = tx.hash().as_slice().try_into().unwrap();
    let version = 0u64.to_le_bytes();
    let funding_out_point = input_out_point.as_slice();
    let message = blake2b_256(
        [
            version.to_vec(),
            funding_out_point.to_vec(),
            tx_hash.to_vec(),
        ]
        .concat(),
    );

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
    println!("signature: {:?}", aggregated_signature_1.to_bytes());

    let witness = [
        version.to_vec(),
        funding_out_point.to_vec(),
        x_only_pub_key.to_vec(),
        aggregated_signature_1.to_bytes().to_vec(),
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
    let mut generator = Generator::new();
    // 42 hours = 4.5 epochs
    let local_delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let local_delay_epoch_key = generator.gen_keypair();
    let revocation_key = generator.gen_keypair();

    let witness_script = [
        local_delay_epoch.as_u64().to_le_bytes().to_vec(),
        blake2b_256(local_delay_epoch_key.1.serialize())[0..20].to_vec(),
        blake2b_256(revocation_key.1.serialize())[0..20].to_vec(),
    ]
    .concat();

    let args = blake2b_256(&witness_script)[0..20].to_vec();

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.into())
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
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
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

    // build transaction with revocation unlock logic
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with revocation key
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = revocation_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [witness_script.clone(), vec![0xFF], signature].concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();
    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with local_delay_epoch unlock logic
    // delay 48 hours
    let since = Since::from_epoch(EpochNumberWithFraction::new(12, 0, 1), false);
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

    // sign with local_delay_epoch_key
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_delay_epoch_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [witness_script, vec![0xFF], signature].concat();

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
    let mut generator = Generator::new();
    // 42 hours = 4.5 epochs
    let local_delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    let local_delay_epoch_key = generator.gen_keypair();
    let revocation_key = generator.gen_keypair();
    let remote_htlc_key1 = generator.gen_keypair();
    let remote_htlc_key2 = generator.gen_keypair();
    let local_htlc_key1 = generator.gen_keypair();
    let local_htlc_key2 = generator.gen_keypair();
    let preimage1 = [42u8; 32];
    let preimage2 = [24u8; 32];
    let payment_amount1 = 5 * BYTE_SHANNONS;
    let payment_amount2 = 8 * BYTE_SHANNONS;
    // timeout after 2024-04-01 01:00:00
    let expiry1 = Since::from_timestamp(1711976400, true).unwrap();
    // timeout after 2024-04-02 01:00:00
    let expiry2 = Since::from_timestamp(1712062800, true).unwrap();

    let witness_script = [
        local_delay_epoch.as_u64().to_le_bytes().to_vec(),
        blake2b_256(local_delay_epoch_key.1.serialize())[0..20].to_vec(),
        blake2b_256(revocation_key.1.serialize())[0..20].to_vec(),
        [0u8].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
        [1u8].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        blake2b_256(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();

    let args = blake2b_256(&witness_script)[0..20].to_vec();

    let lock_script = context
        .build_script(&commitment_lock_out_point, args.into())
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
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();
    let output_lock = Script::new_builder()
        .args(Bytes::from("output_lock").pack())
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity((500 * BYTE_SHANNONS).pack())
            .lock(output_lock.clone())
            .build(),
        CellOutput::new_builder()
            .capacity((500 * BYTE_SHANNONS).pack())
            .lock(output_lock.clone())
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction with revocation unlock logic
    let tx = TransactionBuilder::default()
        .cell_deps(cell_deps.clone())
        .input(input)
        .outputs(outputs.clone())
        .outputs_data(outputs_data.pack())
        .build();

    // sign with revocation key
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = revocation_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [witness_script.clone(), vec![0xFF], signature].concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();
    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with local_delay_epoch unlock logic
    // delay 48 hours
    let since = Since::from_epoch(EpochNumberWithFraction::new(12, 0, 1), false);
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

    // sign with local_delay_epoch_key
    let message: [u8; 32] = tx.hash().as_slice().try_into().unwrap();

    let signature = local_delay_epoch_key
        .0
        .sign_recoverable(&message.into())
        .unwrap()
        .serialize();
    let witness = [witness_script.clone(), vec![0xFF], signature].concat();

    let tx = tx.as_advanced_builder().witness(witness.pack()).build();
    println!("tx: {:?}", tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);

    // build transaction with remote_htlc_pubkey unlock offered pending htlc 1
    let input = CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build();

    let new_witness_script = [
        local_delay_epoch.as_u64().to_le_bytes().to_vec(),
        blake2b_256(local_delay_epoch_key.1.serialize())[0..20].to_vec(),
        blake2b_256(revocation_key.1.serialize())[0..20].to_vec(),
        [1u8].to_vec(),
        payment_amount2.to_le_bytes().to_vec(),
        blake2b_256(preimage2)[0..20].to_vec(),
        blake2b_256(remote_htlc_key2.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key2.1.serialize())[0..20].to_vec(),
        expiry2.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();
    let new_lock_script = lock_script
        .clone()
        .as_builder()
        .args(blake2b_256(&new_witness_script)[0..20].to_vec().pack())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS - payment_amount1).pack())
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
        witness_script.clone(),
        vec![0x00],
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
        .build()];
    let outputs_data = vec![Bytes::new()];
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
        witness_script.clone(),
        vec![0x00],
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

    // build transaction with remote_htlc_pubkey unlock received pending htlc 2
    let since = Since::from_timestamp(1712062800 + 1000, true).unwrap();
    let input = CellInput::new_builder()
        .since(since.as_u64().pack())
        .previous_output(input_out_point.clone())
        .build();

    let new_witness_script = [
        local_delay_epoch.as_u64().to_le_bytes().to_vec(),
        blake2b_256(local_delay_epoch_key.1.serialize())[0..20].to_vec(),
        blake2b_256(revocation_key.1.serialize())[0..20].to_vec(),
        [0u8].to_vec(),
        payment_amount1.to_le_bytes().to_vec(),
        blake2b_256(preimage1)[0..20].to_vec(),
        blake2b_256(remote_htlc_key1.1.serialize())[0..20].to_vec(),
        blake2b_256(local_htlc_key1.1.serialize())[0..20].to_vec(),
        expiry1.as_u64().to_le_bytes().to_vec(),
    ]
    .concat();
    let new_lock_script = lock_script
        .as_builder()
        .args(blake2b_256(&new_witness_script)[0..20].to_vec().pack())
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity((1000 * BYTE_SHANNONS - payment_amount2).pack())
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
    let witness = [witness_script.clone(), vec![0x01], signature].concat();

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
        witness_script.clone(),
        vec![0x01],
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
