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
    ckb_types::{bytes::Bytes, core::ScriptHashType, packed::TransactionReader, prelude::*},
    error::SysError,
    high_level::{
        exec_cell, load_cell_capacity, load_cell_data, load_cell_lock, load_cell_type,
        load_input_since, load_script, load_tx_hash, load_witness,
    },
    since::Since,
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
    InvalidHtlcType,
    ArgsLenError,
    WitnessLenError,
    EmptyWitnessArgsError,
    WitnessHashError,
    InvalidFundingTx,
    InvalidNewVersionCommitmentTx,
    InvalidOutPoint,
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
// min witness script length: 8 (local_delay_epoch) + 20 (local_delay_pubkey_hash) + 1 (pending_htlc_count) = 29
const MIN_WITNESS_SCRIPT_LEN: usize = 29;
// HTLC script length: 1 (htlc_type) + 16 (payment_amount) + 20 (payment_hash) + 20 (remote_htlc_pubkey_hash) + 20 (local_htlc_pubkey_hash) + 8 (htlc_expiry) = 85
const HTLC_SCRIPT_LEN: usize = 85;
const SIGNATURE_LEN: usize = 65;
const PREIMAGE_LEN: usize = 32;
const ZERO_INDEX: &[u8] = &[0, 0, 0, 0];

enum HtlcType {
    Offered,
    Received,
}

enum PaymentHashType {
    Blake2b,
    Sha256,
}

struct Htlc<'a>(&'a [u8]);

impl<'a> Htlc<'a> {
    pub fn htlc_type(&self) -> HtlcType {
        if self.0[0] & 0b00000001 == 0 {
            HtlcType::Offered
        } else {
            HtlcType::Received
        }
    }

    pub fn payment_hash_type(&self) -> PaymentHashType {
        if (self.0[0] >> 1) & 0b0000001 == 0 {
            PaymentHashType::Blake2b
        } else {
            PaymentHashType::Sha256
        }
    }

    pub fn payment_amount(&self) -> u128 {
        u128::from_le_bytes(self.0[1..17].try_into().unwrap())
    }

    pub fn payment_hash(&self) -> &'a [u8] {
        &self.0[17..37]
    }

    pub fn remote_htlc_pubkey_hash(&self) -> &'a [u8] {
        &self.0[37..57]
    }

    pub fn local_htlc_pubkey_hash(&self) -> &'a [u8] {
        &self.0[57..77]
    }

    pub fn htlc_expiry(&self) -> u64 {
        u64::from_le_bytes(self.0[77..85].try_into().unwrap())
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
    if args.len() != 60 {
        return Err(Error::ArgsLenError);
    }

    let mut witness = load_witness(0, Source::GroupInput)?;
    if witness
        .drain(0..EMPTY_WITNESS_ARGS.len())
        .collect::<Vec<_>>()
        != EMPTY_WITNESS_ARGS
    {
        return Err(Error::EmptyWitnessArgsError);
    }
    let unlock_type = witness.remove(0);
    if unlock_type == 0xFF {
        // revocation unlock process
        // 1. verify the funding tx is correct
        let funding_tx_len: [u8; 4] = witness[0..4].try_into().unwrap();
        let funding_tx_len: usize = u32::from_le_bytes(funding_tx_len) as usize;
        let funding_tx = TransactionReader::from_slice(&witness[0..funding_tx_len])
            .map_err(|_e| Error::InvalidFundingTx)?;
        let funding_tx_hash = args[8..40].as_ref();
        if funding_tx.calc_tx_hash().as_slice() != funding_tx_hash {
            return Err(Error::InvalidFundingTx);
        }

        // 2. verify the commitment txs consume the same funding cell
        let new_version_commitment_tx = TransactionReader::from_slice(&witness[funding_tx_len..])
            .map_err(|_e| Error::InvalidNewVersionCommitmentTx)?;
        let new_version_commitment_tx_out_point = new_version_commitment_tx
            .raw()
            .inputs()
            .get(0)
            .unwrap()
            .previous_output();
        if new_version_commitment_tx_out_point.tx_hash().as_slice() != funding_tx_hash
            || new_version_commitment_tx_out_point.index().as_slice() != ZERO_INDEX
        {
            return Err(Error::InvalidOutPoint);
        }

        // 3. verify the new_version_commitment_tx has the higher version number
        let current_version: [u8; 8] = args[0..8].try_into().unwrap();
        let new_version: [u8; 8] = new_version_commitment_tx
            .raw()
            .outputs()
            .get(0)
            .unwrap()
            .lock()
            .args()
            .raw_data()[0..8]
            .try_into()
            .unwrap();
        if current_version >= new_version {
            return Err(Error::InvalidNewVersionCommitmentTx);
        }

        // 4. verify the output cell is correct
        let output_lock = load_cell_lock(0, Source::Output)?;
        let expected_lock = new_version_commitment_tx
            .raw()
            .outputs()
            .get(1)
            .unwrap()
            .lock()
            .to_entity();
        if output_lock.as_slice() != expected_lock.as_slice() {
            return Err(Error::OutputLockError);
        }

        let output_type = load_cell_type(0, Source::Output)?.pack();
        let expected_type = new_version_commitment_tx
            .raw()
            .outputs()
            .get(1)
            .unwrap()
            .type_()
            .to_entity();
        if output_type.as_slice() != expected_type.as_slice() {
            return Err(Error::OutputTypeError);
        }

        let output_capacity = load_cell_capacity(0, Source::Output)?;
        if output_capacity != load_cell_capacity(0, Source::GroupInput)? {
            return Err(Error::OutputCapacityError);
        }

        let output_data = load_cell_data(0, Source::Output)?;
        if output_data != load_cell_data(0, Source::GroupInput)? {
            return Err(Error::OutputUdtAmountError);
        }

        // 5. verify the new_version_commitment_tx's signature is correct
        let pubkey_hash: [u8; 20] = funding_tx
            .raw()
            .outputs()
            .get(0)
            .unwrap()
            .lock()
            .args()
            .raw_data()[0..20]
            .try_into()
            .unwrap();

        let new_version_commitment_tx_hash = new_version_commitment_tx.calc_tx_hash();
        let mut new_version_commitment_witness = new_version_commitment_tx
            .witnesses()
            .get(0)
            .unwrap()
            .raw_data()
            .to_vec();
        new_version_commitment_witness.drain(0..EMPTY_WITNESS_ARGS.len());

        // AuthAlgorithmIdSchnorr = 7
        let algorithm_id_str = CString::new(encode([7u8])).unwrap();
        let signature_str = CString::new(encode(new_version_commitment_witness)).unwrap();
        let message_str = CString::new(encode(new_version_commitment_tx_hash.as_slice())).unwrap();
        let pubkey_hash_str = CString::new(encode(pubkey_hash)).unwrap();

        let args = [
            algorithm_id_str.as_c_str(),
            signature_str.as_c_str(),
            message_str.as_c_str(),
            pubkey_hash_str.as_c_str(),
        ];

        exec_cell(&AUTH_CODE_HASH, ScriptHashType::Data1, &args).map_err(|_| Error::AuthError)?;
        return Ok(());
    } else {
        // normal unlock process
        // verify the hash of the witness script part is equal to the script args
        let witness_len = witness.len();
        let pending_htlc_count = witness[MIN_WITNESS_SCRIPT_LEN - 1] as usize;
        let witness_script_len = MIN_WITNESS_SCRIPT_LEN + pending_htlc_count * HTLC_SCRIPT_LEN;
        if witness_len < witness_script_len {
            return Err(Error::WitnessLenError);
        }
        if blake2b_256(&witness[0..witness_script_len])[0..20] != args[40..60] {
            return Err(Error::WitnessHashError);
        }

        let raw_since_value = load_input_since(0, Source::GroupInput)?;
        let message = load_tx_hash()?;
        let mut signature = [0u8; 65];
        let mut pubkey_hash = [0u8; 20];

        if unlock_type == 0xFE {
            // non-pending HTLC unlock process
            let since = Since::new(raw_since_value);
            let local_delay_epoch =
                Since::new(u64::from_le_bytes(witness[0..8].try_into().unwrap()));
            if since >= local_delay_epoch {
                let expected_witness_len = witness_script_len + SIGNATURE_LEN;
                if witness_len != expected_witness_len {
                    return Err(Error::WitnessLenError);
                }
                signature.copy_from_slice(&witness[witness_script_len..]);
                pubkey_hash.copy_from_slice(&witness[8..28]);
            } else {
                return Err(Error::InvalidSince);
            }
        } else {
            // pending HTLC unlock process
            let unlock_htlc = unlock_type as usize;
            if unlock_htlc >= pending_htlc_count {
                return Err(Error::InvalidUnlockType);
            }

            if raw_since_value == 0 {
                let expected_witness_len = witness_script_len + SIGNATURE_LEN + PREIMAGE_LEN;
                if witness_len != expected_witness_len {
                    return Err(Error::WitnessLenError);
                }
                signature.copy_from_slice(
                    &witness[witness_script_len..witness_script_len + SIGNATURE_LEN],
                );
            } else {
                let expected_witness_len = witness_script_len + SIGNATURE_LEN;
                if witness_len != expected_witness_len {
                    return Err(Error::WitnessLenError);
                }
                signature.copy_from_slice(&witness[witness_script_len..]);
            }

            let mut new_amount = if type_script.is_some() {
                let input_cell_data = load_cell_data(0, Source::GroupInput)?;
                u128::from_le_bytes(input_cell_data[0..16].try_into().unwrap())
            } else {
                load_cell_capacity(0, Source::GroupInput)? as u128
            };
            let mut new_witness_script: Vec<&[u8]> = Vec::new();
            new_witness_script.push(&witness[0..MIN_WITNESS_SCRIPT_LEN - 1]);
            let new_pending_htlc_count = [(pending_htlc_count - 1) as u8];
            new_witness_script.push(&new_pending_htlc_count);

            for (i, htlc_script) in witness[MIN_WITNESS_SCRIPT_LEN..witness_script_len]
                .chunks(HTLC_SCRIPT_LEN)
                .enumerate()
            {
                let htlc = Htlc(htlc_script);
                if unlock_htlc == i {
                    match htlc.htlc_type() {
                        HtlcType::Offered => {
                            if raw_since_value == 0 {
                                // when input since is 0, it means the unlock logic is for remote_htlc pubkey and preimage
                                let preimage = &witness[witness_script_len + SIGNATURE_LEN..];
                                if match htlc.payment_hash_type() {
                                    PaymentHashType::Blake2b => {
                                        htlc.payment_hash() != &blake2b_256(preimage)[0..20]
                                    }
                                    PaymentHashType::Sha256 => {
                                        htlc.payment_hash() != &Sha256::digest(preimage)[0..20]
                                    }
                                } {
                                    return Err(Error::PreimageError);
                                }
                                new_amount -= htlc.payment_amount();
                                pubkey_hash.copy_from_slice(htlc.remote_htlc_pubkey_hash());
                            } else {
                                // when input since is not 0, it means the unlock logic is for local_htlc pubkey and htlc expiry
                                let since = Since::new(raw_since_value);
                                let htlc_expiry = Since::new(htlc.htlc_expiry());
                                if since >= htlc_expiry {
                                    pubkey_hash.copy_from_slice(htlc.local_htlc_pubkey_hash());
                                } else {
                                    return Err(Error::InvalidSince);
                                }
                            }
                        }
                        HtlcType::Received => {
                            if raw_since_value == 0 {
                                // when input since is 0, it means the unlock logic is for local_htlc pubkey and preimage
                                let preimage = &witness[witness_script_len + SIGNATURE_LEN..];
                                if match htlc.payment_hash_type() {
                                    PaymentHashType::Blake2b => {
                                        htlc.payment_hash() != &blake2b_256(preimage)[0..20]
                                    }
                                    PaymentHashType::Sha256 => {
                                        htlc.payment_hash() != &Sha256::digest(preimage)[0..20]
                                    }
                                } {
                                    return Err(Error::PreimageError);
                                }
                                pubkey_hash.copy_from_slice(htlc.local_htlc_pubkey_hash());
                            } else {
                                // when input since is not 0, it means the unlock logic is for remote_htlc pubkey and htlc expiry
                                let since = Since::new(raw_since_value);
                                let htlc_expiry = Since::new(htlc.htlc_expiry());
                                if since >= htlc_expiry {
                                    new_amount -= htlc.payment_amount();
                                    pubkey_hash.copy_from_slice(htlc.remote_htlc_pubkey_hash());
                                } else {
                                    return Err(Error::InvalidSince);
                                }
                            }
                        }
                    }
                } else {
                    new_witness_script.push(htlc_script);
                }
            }

            // verify the first output cell's lock script is correct
            let output_lock = load_cell_lock(0, Source::Output)?;
            let expected_lock_args = [
                &args[0..40],
                blake2b_256(new_witness_script.concat())[0..20].as_ref(),
            ]
            .concat()
            .pack();
            if output_lock.code_hash() != script.code_hash()
                || output_lock.hash_type() != script.hash_type()
                || output_lock.args() != expected_lock_args
            {
                return Err(Error::OutputLockError);
            }

            match type_script {
                Some(udt_script) => {
                    // verify the first output cell's capacity, type script and udt amount are correct
                    let output_capacity = load_cell_capacity(0, Source::Output)?;
                    let input_capacity = load_cell_capacity(0, Source::GroupInput)?;
                    if output_capacity != input_capacity {
                        return Err(Error::OutputCapacityError);
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

        // AuthAlgorithmIdCkb = 0
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

        exec_cell(&AUTH_CODE_HASH, ScriptHashType::Data1, &args).map_err(|_| Error::AuthError)?;
        Ok(())
    }
}
