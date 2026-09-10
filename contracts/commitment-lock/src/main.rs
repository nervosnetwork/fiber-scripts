#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

use ckb_hash::blake2b_256;
#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

use alloc::{ffi::CString, vec::Vec};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    error::SysError,
    high_level::{
        QueryIter, load_cell, load_cell_capacity, load_cell_data, load_cell_lock, load_cell_type,
        load_input_since, load_script, load_transaction, load_witness, spawn_cell,
    },
    since::{EpochNumberWithFraction, LockValue, Since},
    syscalls::wait,
};
use hex::encode;
use sha2::{Digest, Sha256};

include!(concat!(env!("OUT_DIR"), "/auth_code_hash.rs"));

#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    MultipleInputs,
    InvalidSince,
    InvalidUnlockType,
    InvalidWithPreimageFlag,
    InvalidSettlementCount,
    InvalidUnlockCount,
    InvalidExpiry,
    ArgsLenError,
    WitnessLenError,
    EmptyWitnessArgsError,
    WitnessHashError,
    InvalidFundingTx,
    InvalidRevocationVersion,
    OutputCapacityError,
    OutputLockError,
    OutputTypeError,
    OutputUdtAmountError,
    PreimageError,
    AuthError,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        match err {
            SysError::IndexOutOfBound => Self::IndexOutOfBound,
            SysError::ItemMissing => Self::ItemMissing,
            SysError::LengthNotEnough(_) => Self::LengthNotEnough,
            SysError::Encoding => Self::Encoding,
            SysError::Unknown(err_code) => panic!("unexpected sys error {}", err_code),
            _ => panic!("unreachable spawn related sys error"),
        }
    }
}

pub fn program_entry() -> i8 {
    match auth() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

// a placeholder for empty witness args, to resolve the issue of xudt compatibility
const EMPTY_WITNESS_ARGS: [u8; 16] = [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0];
// HTLC script length: 1 (htlc_type) + 16 (payment_amount) + payment_hash + 20
// (remote_htlc_pubkey_hash) + 20 (local_htlc_pubkey_hash) + 8 (htlc_expiry)
const SIGNATURE_LEN: usize = 65;
const PREIMAGE_LEN: usize = 32;

// feature bitmap bit0: full 32-byte payment hash committed on-chain
const FEATURE_ONCHAIN_FULL_PAYMENT_HASH: u8 = 0b0000_0001;

#[derive(Copy, Clone)]
struct HtlcLayout {
    htlc_script_len: usize,
    payment_hash_len: usize,
}

const HTLC_LAYOUT_LEGACY: HtlcLayout = HtlcLayout {
    htlc_script_len: 85,
    payment_hash_len: 20,
};

const HTLC_LAYOUT_V1: HtlcLayout = HtlcLayout {
    htlc_script_len: 97, // 1 (htlc_type) + 16 (payment_amount) + 32 (payment_hash)
    // + 20 (remote_htlc_pubkey_hash) + 20 (local_htlc_pubkey_hash) + 8 (htlc_expiry)
    payment_hash_len: 32,
};

fn resolve_htlc_layout(args: &[u8]) -> Result<HtlcLayout, Error> {
    match args.len() {
        57 => Ok(HTLC_LAYOUT_LEGACY),
        58 if args[57] == FEATURE_ONCHAIN_FULL_PAYMENT_HASH => Ok(HTLC_LAYOUT_V1),
        _ => Err(Error::ArgsLenError),
    }
}

fn preimage_matches(hash_type: PaymentHashType, committed_hash: &[u8], preimage: &[u8]) -> bool {
    let digest = match hash_type {
        PaymentHashType::Blake2b => blake2b_256(preimage),
        PaymentHashType::Sha256 => Sha256::digest(preimage).into(),
    };
    committed_hash == &digest[..committed_hash.len()]
}

enum HtlcType {
    Offered,
    Received,
}

enum PaymentHashType {
    Blake2b,
    Sha256,
}

struct Htlc<'a> {
    data: &'a [u8],
    payment_hash_len: usize,
}

impl<'a> Htlc<'a> {
    fn new(data: &'a [u8], layout: HtlcLayout) -> Self {
        Self {
            data,
            payment_hash_len: layout.payment_hash_len,
        }
    }

    fn htlc_type(&self) -> HtlcType {
        if self.data[0] & 0b00000001 == 0 {
            HtlcType::Offered
        } else {
            HtlcType::Received
        }
    }

    fn payment_hash_type(&self) -> PaymentHashType {
        if (self.data[0] >> 1) & 0b0000001 == 0 {
            PaymentHashType::Blake2b
        } else {
            PaymentHashType::Sha256
        }
    }

    fn payment_amount(&self) -> u128 {
        u128::from_le_bytes(self.data[1..17].try_into().unwrap())
    }

    fn payment_hash(&self) -> &'a [u8] {
        &self.data[17..17 + self.payment_hash_len]
    }

    fn remote_htlc_pubkey_hash(&self) -> [u8; 20] {
        let off = 17 + self.payment_hash_len;
        self.data[off..off + 20].try_into().unwrap()
    }

    fn local_htlc_pubkey_hash(&self) -> [u8; 20] {
        let off = 17 + self.payment_hash_len + 20;
        self.data[off..off + 20].try_into().unwrap()
    }

    fn htlc_expiry(&self) -> u64 {
        let off = 17 + self.payment_hash_len + 40;
        u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap())
    }
}

struct Settlement<'a>(&'a [u8]);

impl Settlement<'_> {
    fn unlock_type(&self) -> u8 {
        self.0[0]
    }

    fn with_preimage(&self) -> bool {
        self.0[1] == 1
    }

    fn signature(&self) -> [u8; SIGNATURE_LEN] {
        self.0[2..2 + SIGNATURE_LEN].try_into().unwrap()
    }

    fn preimage(&self) -> &[u8] {
        if self.with_preimage() {
            &self.0[2 + SIGNATURE_LEN..2 + SIGNATURE_LEN + PREIMAGE_LEN]
        } else {
            &[]
        }
    }
}

fn auth() -> Result<(), Error> {
    // since local_delay_pubkey is derived, the scripts are usually unique, to simplify the implementation of the following unlocking logic, we check the number of inputs should be 1
    if load_input_since(1, Source::GroupInput).is_ok() {
        return Err(Error::MultipleInputs);
    }

    // no need to check the type script is sudt / xudt or not, because the offchain tx collaboration will ensure the correct type script.
    let type_script = load_cell_type(0, Source::GroupInput)?;

    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    let layout = resolve_htlc_layout(args.as_ref())?;
    let is_first_settlement = args[56] == 0x00;

    let mut witness = load_witness(0, Source::GroupInput)?;
    if witness
        .drain(0..EMPTY_WITNESS_ARGS.len())
        .collect::<Vec<_>>()
        != EMPTY_WITNESS_ARGS
    {
        return Err(Error::EmptyWitnessArgsError);
    }
    let unlock_count = witness.remove(0);
    if unlock_count == 0x00 {
        // revocation unlock process

        // verify version
        let current_version: [u8; 8] = args[28..36].try_into().unwrap();
        let new_version: [u8; 8] = witness[0..8].try_into().unwrap();
        if current_version > new_version {
            return Err(Error::InvalidRevocationVersion);
        }

        // verify signature, we are using the same signature verification logic as open tx, only hash the 1st output
        let output = load_cell(0, Source::Output)?;
        let output_data = load_cell_data(0, Source::Output)?;
        let message = blake2b_256(
            [
                output.as_slice(),
                (output_data.len() as u32).to_le_bytes().as_ref(),
                output_data.as_slice(),
                &args[0..28],
                new_version.as_ref(),
            ]
            .concat(),
        );
        let pubkey_hash = &args[0..20];

        // AuthAlgorithmIdSchnorr = 7
        let algorithm_id_str = CString::new(encode([7u8])).unwrap();
        let signature_str = CString::new(encode(&witness[8..])).unwrap();
        let message_str = CString::new(encode(message)).unwrap();
        let pubkey_hash_str = CString::new(encode(pubkey_hash)).unwrap();

        let args = [
            algorithm_id_str.as_c_str(),
            signature_str.as_c_str(),
            message_str.as_c_str(),
            pubkey_hash_str.as_c_str(),
        ];

        let pid = spawn_cell(&AUTH_CODE_HASH, ScriptHashType::Data1, &args, &[])
            .map_err(|_| Error::AuthError)?;
        let result = wait(pid).map_err(|_| Error::AuthError)?;
        if result != 0 {
            return Err(Error::AuthError);
        }
        Ok(())
    } else {
        // settlement unlock process
        let pending_htlc_count = witness[0] as usize;
        // 1 (pending_htlc_count) + pending_htlc_count * HtlcLayout::htlc_script_len
        let pending_htlcs_len = 1 + pending_htlc_count * layout.htlc_script_len;
        // settlement_remote_pubkey_hash + settlement_remote_amount + settlement_local_pubkey_hash + settlement_local_amount
        let settlement_script_len = pending_htlcs_len + 72;
        if witness.len() < settlement_script_len {
            return Err(Error::WitnessLenError);
        }
        // verify the selettlement script hash is equal to the script args
        if blake2b_256(&witness[0..settlement_script_len])[0..20] != args[36..56] {
            return Err(Error::WitnessHashError);
        }

        let mut settlements = Vec::new();
        let mut settlement_htlc_count = 0;
        let mut i = settlement_script_len;
        while witness.len() > i {
            let unlock_type = witness[i];
            if unlock_type >= pending_htlc_count as u8 && unlock_type != 0xFE && unlock_type != 0xFF
            {
                return Err(Error::InvalidUnlockType);
            } else if unlock_type < pending_htlc_count as u8 {
                settlement_htlc_count += 1;
            }
            let with_preimage = witness[i + 1];
            if with_preimage == 0 {
                settlements.push(Settlement(&witness[i..i + 2 + SIGNATURE_LEN]));
                i += 2 + SIGNATURE_LEN;
            } else if with_preimage == 1 {
                settlements.push(Settlement(
                    &witness[i..i + 2 + SIGNATURE_LEN + PREIMAGE_LEN],
                ));
                i += 2 + SIGNATURE_LEN + PREIMAGE_LEN;
            } else {
                return Err(Error::InvalidWithPreimageFlag);
            }
        }

        if settlements.is_empty() {
            return Err(Error::InvalidSettlementCount);
        }

        let raw_since_value = load_expiry_raw_since_value();
        let delay_epoch = Since::new(u64::from_le_bytes(args[20..28].try_into().unwrap()));
        let message = {
            let tx = load_transaction()?
                .raw()
                .as_builder()
                .cell_deps(Default::default())
                .build();
            blake2b_256(tx.as_slice())
        };

        let mut new_amount = if type_script.is_some() {
            let input_cell_data = load_cell_data(0, Source::GroupInput)?;
            u128::from_le_bytes(input_cell_data[0..16].try_into().unwrap())
        } else {
            load_cell_capacity(0, Source::GroupInput)? as u128
        };

        let mut new_settlement_script: Vec<&[u8]> = Vec::new();
        let new_pending_htlc_count = [(pending_htlc_count - settlement_htlc_count) as u8];
        new_settlement_script.push(&new_pending_htlc_count);

        let mut signatures_to_verify = Vec::new();

        for (i, htlc_script) in witness[1..pending_htlcs_len]
            .chunks(layout.htlc_script_len)
            .enumerate()
        {
            if !settlements.is_empty() && settlements[0].unlock_type() == i as u8 {
                let htlc = Htlc::new(htlc_script, layout);
                match htlc.htlc_type() {
                    HtlcType::Offered => {
                        if raw_since_value == 0 {
                            // Preimage unlock delay_epoch should be shorter than the expiry unlock, we use 1/3 of delay_epoch
                            if is_first_settlement && !check_input_since(mul(delay_epoch, 1, 3)) {
                                return Err(Error::InvalidSince);
                            }
                            // when input since is 0, it means the unlock logic is for remote_htlc pubkey and preimage
                            let preimage = settlements[0].preimage();
                            if !preimage_matches(
                                htlc.payment_hash_type(),
                                htlc.payment_hash(),
                                preimage,
                            ) {
                                return Err(Error::PreimageError);
                            }
                            new_amount = new_amount.saturating_sub(htlc.payment_amount());
                            signatures_to_verify.push((
                                settlements.remove(0).signature(),
                                htlc.remote_htlc_pubkey_hash(),
                            ));
                        } else {
                            // Expiry unlock delay_epoch should be shorter than non-pending unlock and longer than the preimage unlock, we use 2/3 of delay_epoch
                            if is_first_settlement && !check_input_since(mul(delay_epoch, 2, 3)) {
                                return Err(Error::InvalidSince);
                            }
                            // when input since is not 0, it means the unlock logic is for local_htlc pubkey and htlc expiry
                            let since = Since::new(raw_since_value);
                            let htlc_expiry = Since::new(htlc.htlc_expiry());
                            if since >= htlc_expiry {
                                new_amount = new_amount.saturating_sub(htlc.payment_amount());
                                signatures_to_verify.push((
                                    settlements.remove(0).signature(),
                                    htlc.local_htlc_pubkey_hash(),
                                ));
                            } else {
                                return Err(Error::InvalidExpiry);
                            }
                        }
                    }
                    HtlcType::Received => {
                        if raw_since_value == 0 {
                            // Preimage unlock delay_epoch should be shorter than the expiry unlock, we use 1/3 of delay_epoch
                            if is_first_settlement && !check_input_since(mul(delay_epoch, 1, 3)) {
                                return Err(Error::InvalidSince);
                            }
                            // when input since is 0, it means the unlock logic is for local_htlc pubkey and preimage
                            let preimage = settlements[0].preimage();
                            if !preimage_matches(
                                htlc.payment_hash_type(),
                                htlc.payment_hash(),
                                preimage,
                            ) {
                                return Err(Error::PreimageError);
                            }
                            new_amount = new_amount.saturating_sub(htlc.payment_amount());
                            signatures_to_verify.push((
                                settlements.remove(0).signature(),
                                htlc.local_htlc_pubkey_hash(),
                            ));
                        } else {
                            // Expiry unlock delay_epoch should be shorter than non-pending unlock and longer than the preimage unlock, we use 2/3 of delay_epoch
                            if is_first_settlement && !check_input_since(mul(delay_epoch, 2, 3)) {
                                return Err(Error::InvalidSince);
                            }
                            // when input since is not 0, it means the unlock logic is for remote_htlc pubkey and htlc expiry
                            let since = Since::new(raw_since_value);
                            let htlc_expiry = Since::new(htlc.htlc_expiry());
                            if since >= htlc_expiry {
                                new_amount = new_amount.saturating_sub(htlc.payment_amount());
                                signatures_to_verify.push((
                                    settlements.remove(0).signature(),
                                    htlc.remote_htlc_pubkey_hash(),
                                ));
                            } else {
                                return Err(Error::InvalidExpiry);
                            }
                        }
                    }
                }
            } else {
                new_settlement_script.push(htlc_script);
            }
        }

        // settlement for local or remote parties
        let mut two_parties_all_settled = false;
        let mut is_party_settlement = false;
        if settlements.len() == 1 {
            let settlement = settlements.remove(0);
            match settlement.unlock_type() {
                0xFE => {
                    // remote settlement should wait for delay_epoch
                    if is_first_settlement && !check_input_since(delay_epoch) {
                        return Err(Error::InvalidSince);
                    }
                    let settlement_remote_pubkey_hash: [u8; 20] = witness
                        [pending_htlcs_len..pending_htlcs_len + 20]
                        .try_into()
                        .unwrap();
                    let settlement_remote_amount = u128::from_le_bytes(
                        witness[pending_htlcs_len + 20..pending_htlcs_len + 36]
                            .try_into()
                            .unwrap(),
                    );
                    new_amount = new_amount.saturating_sub(settlement_remote_amount);

                    new_settlement_script.push(&[0u8; 36]);
                    new_settlement_script
                        .push(&witness[pending_htlcs_len + 36..pending_htlcs_len + 72]);
                    signatures_to_verify
                        .push((settlement.signature(), settlement_remote_pubkey_hash));

                    two_parties_all_settled =
                        witness[pending_htlcs_len + 36..pending_htlcs_len + 72] == [0u8; 36];
                    is_party_settlement = true;
                }
                0xFF => {
                    // local settlement should wait for delay_epoch
                    if is_first_settlement && !check_input_since(delay_epoch) {
                        return Err(Error::InvalidSince);
                    }
                    let settlement_local_pubkey_hash: [u8; 20] = witness
                        [pending_htlcs_len + 36..pending_htlcs_len + 56]
                        .try_into()
                        .unwrap();
                    let settlement_local_amount = u128::from_le_bytes(
                        witness[pending_htlcs_len + 56..pending_htlcs_len + 72]
                            .try_into()
                            .unwrap(),
                    );
                    new_amount = new_amount.saturating_sub(settlement_local_amount);

                    new_settlement_script.push(&witness[pending_htlcs_len..pending_htlcs_len + 36]);
                    new_settlement_script.push(&[0u8; 36]);
                    signatures_to_verify
                        .push((settlement.signature(), settlement_local_pubkey_hash));

                    two_parties_all_settled =
                        witness[pending_htlcs_len..pending_htlcs_len + 36] == [0u8; 36];
                    is_party_settlement = true;
                }
                _unlock => {
                    return Err(Error::InvalidUnlockType);
                }
            }
        } else if settlements.is_empty() {
            new_settlement_script.push(&witness[pending_htlcs_len..pending_htlcs_len + 72]);
        } else {
            return Err(Error::InvalidSettlementCount);
        }

        // verify the first output cell's lock script and capacity are correct
        if new_amount > 0 && !two_parties_all_settled {
            let output_lock = load_cell_lock(0, Source::Output)?;
            let expected_lock_args = [
                &args[0..36],
                blake2b_256(new_settlement_script.concat())[0..20].as_ref(),
                &[0x01], // 0x01 means new cell is created for subsequent commitment cell unlock
            ]
            .concat()
            .pack();
            if output_lock.code_hash() != script.code_hash() {
                return Err(Error::Encoding);
            }
            if output_lock.hash_type() != script.hash_type() {
                return Err(Error::ItemMissing);
            }
            if output_lock.args() != expected_lock_args {
                return Err(Error::OutputLockError);
            }

            match type_script {
                Some(udt_script) => {
                    // verify the first output cell's capacity, type script and udt amount are correct
                    if !is_party_settlement {
                        let output_capacity = load_cell_capacity(0, Source::Output)?;
                        let input_capacity = load_cell_capacity(0, Source::GroupInput)?;
                        if output_capacity != input_capacity {
                            return Err(Error::OutputCapacityError);
                        }
                    }

                    let output_type = load_cell_type(0, Source::Output)?;
                    if output_type != Some(udt_script) {
                        return Err(Error::OutputTypeError);
                    }

                    let output_data = load_cell_data(0, Source::Output)?;
                    let output_amount = u128::from_le_bytes(output_data[0..16].try_into().unwrap());
                    if output_amount != new_amount {
                        return Err(Error::OutputUdtAmountError);
                    }
                }
                None => {
                    // verify the first output cell's capacity is correct
                    let output_capacity = load_cell_capacity(0, Source::Output)? as u128;
                    if output_capacity != new_amount {
                        return Err(Error::OutputCapacityError);
                    }
                }
            }
        }

        if signatures_to_verify.is_empty() {
            return Err(Error::InvalidUnlockCount);
        }

        // AuthAlgorithmIdCkb = 0
        for (signature, pubkey_hash) in signatures_to_verify {
            let algorithm_id_str = CString::new(encode([0u8])).unwrap();
            let signature_str = CString::new(encode(signature)).unwrap();
            let message_str = CString::new(encode(message)).unwrap();
            let pubkey_hash_str = CString::new(encode(pubkey_hash)).unwrap();

            let args = [
                algorithm_id_str.as_c_str(),
                signature_str.as_c_str(),
                message_str.as_c_str(),
                pubkey_hash_str.as_c_str(),
            ];

            let pid = spawn_cell(&AUTH_CODE_HASH, ScriptHashType::Data1, &args, &[])
                .map_err(|_| Error::AuthError)?;
            let result = wait(pid).map_err(|_| Error::AuthError)?;
            if result != 0 {
                return Err(Error::AuthError);
            }
        }
        Ok(())
    }
}

// Check if input `since` is a relative epoch and >= `delay_epoch`.
fn check_input_since(delay_epoch: Since) -> bool {
    let raw_since = load_input_since(0, Source::GroupInput).unwrap_or_default();
    let since = Since::new(raw_since);
    since
        .extract_lock_value()
        .map(|lock_value| matches!(lock_value, LockValue::EpochNumberWithFraction(_)))
        .unwrap_or_default()
        && since.is_relative()
        && since >= delay_epoch
}

fn load_expiry_raw_since_value() -> u64 {
    QueryIter::new(load_input_since, Source::Input)
        .find(|&raw_since| {
            let since = Since::new(raw_since);
            matches!(since.extract_lock_value(), Some(LockValue::Timestamp(_)) if since.is_absolute())
        })
        .unwrap_or_default()
}

// Calculate the product of delay_epoch and a fraction
fn mul(delay_epoch: Since, numerator: u64, denominator: u64) -> Since {
    // delay_epoch's format is checked in offchain code, we can safely unwrap here
    let delay = delay_epoch.extract_lock_value().unwrap().epoch().unwrap();
    let full_numerator = numerator * (delay.number() * delay.length() + delay.index());
    let new_denominator = denominator * delay.length();
    let new_integer = full_numerator / new_denominator;
    let new_numerator = full_numerator % new_denominator;

    // nomalize the fraction (max epoch length is 1800)
    let scale_factor = if new_denominator > 1800 {
        new_denominator / 1800 + 1
    } else {
        1
    };

    Since::from_epoch(
        EpochNumberWithFraction::new(
            new_integer,
            new_numerator / scale_factor,
            new_denominator / scale_factor,
        ),
        false,
    )
}

#[test]
fn test_mul() {
    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(7, 60, 100), false);
    // 7.6 * 1 / 3 = 2.533333333333333 = 2 (epoch) + 160 (index) / 300 (length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(2, 160, 300), false),
        mul(delay_epoch, 1, 3)
    );
    // 7.6 * 2 / 3 = 5.066666666666666 = 5 (epoch) + 20 (index) / 300 (length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(5, 20, 300), false),
        mul(delay_epoch, 2, 3)
    );

    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(7, 700, 2100), false);
    // 7.3333333333 * 1 / 3 = 2.44444444444444 = 2 (epoch) + 700 (normalized index) / 1575 (normalized length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(2, 700, 1575), false),
        mul(delay_epoch, 1, 3)
    );
    // 7.3333333333 * 2 / 3 = 4.888888888866666 = 4 (epoch) + 1400 (normalized index) / 1575 (normalized length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(4, 1400, 1575), false),
        mul(delay_epoch, 2, 3)
    );

    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(10, 1, 2), false);
    // 10.5 * 1 / 3 = 3.5 = 3 (epoch) + 3 (index) / 6 (length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(3, 3, 6), false),
        mul(delay_epoch, 1, 3)
    );
    // 10.5 * 2 / 3 = 7.0 = 7 (epoch) + 0 (index) / 6 (length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(7, 0, 6), false),
        mul(delay_epoch, 2, 3)
    );

    let delay_epoch = Since::from_epoch(EpochNumberWithFraction::new(5, 42, 99), false);
    // 5.4242424242 * 1 / 3 = 1.80808080808 = 1 (epoch) + 240 (index) / 297 (length)
    assert_eq!(
        Since::from_epoch(EpochNumberWithFraction::new(1, 240, 297), false),
        mul(delay_epoch, 1, 3)
    );
}
