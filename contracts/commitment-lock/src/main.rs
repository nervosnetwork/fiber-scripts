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
        exec_cell, load_cell, load_cell_capacity, load_cell_data, load_cell_lock, load_cell_type,
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
    InvalidRevocationVersion,
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
// HTLC script length: 1 (htlc_type) + 16 (payment_amount) + 20 (payment_hash) + 20 (remote_htlc_pubkey_hash) + 20 (local_htlc_pubkey_hash) + 8 (htlc_expiry) = 85
const HTLC_SCRIPT_LEN: usize = 85;
const SIGNATURE_LEN: usize = 65;
const PREIMAGE_LEN: usize = 32;

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
    if args.len() != 36 && args.len() != 56 {
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

        exec_cell(&AUTH_CODE_HASH, ScriptHashType::Data1, &args).map_err(|_| Error::AuthError)?;
        return Ok(());
    } else if unlock_type == 0xFE {
        // non-pending HTLC unlock process

        let raw_since_value = load_input_since(0, Source::GroupInput)?;
        let since = Since::new(raw_since_value);
        let delay_epoch = Since::new(u64::from_le_bytes(args[20..28].try_into().unwrap()));
        if since >= delay_epoch {
            // verify signature, we are using the same signature verification logic as open tx, only hash the 1st and 2nd output
            // TODO we may add a check to ensure the 3rd output cell's lock script is same as the 1st output cell's lock script, to resolve the issue of pending timeout HTLC
            let to_local_output = load_cell(0, Source::Output)?;
            let to_local_output_data = load_cell_data(0, Source::Output)?;
            let to_remote_output = load_cell(1, Source::Output)?;
            let to_remote_output_data = load_cell_data(1, Source::Output)?;
            let message = blake2b_256(
                [
                    to_local_output.as_slice(),
                    (to_local_output_data.len() as u32).to_le_bytes().as_ref(),
                    to_local_output_data.as_slice(),
                    to_remote_output.as_slice(),
                    (to_remote_output_data.len() as u32).to_le_bytes().as_ref(),
                    to_remote_output_data.as_slice(),
                    &args[0..36],
                ]
                .concat(),
            );
            let pubkey_hash = &args[0..20];

            // AuthAlgorithmIdSchnorr = 7
            let algorithm_id_str = CString::new(encode([7u8])).unwrap();
            let signature_str = CString::new(encode(&witness)).unwrap();
            let message_str = CString::new(encode(message)).unwrap();
            let pubkey_hash_str = CString::new(encode(pubkey_hash)).unwrap();

            let args = [
                algorithm_id_str.as_c_str(),
                signature_str.as_c_str(),
                message_str.as_c_str(),
                pubkey_hash_str.as_c_str(),
            ];

            exec_cell(&AUTH_CODE_HASH, ScriptHashType::Data1, &args)
                .map_err(|_| Error::AuthError)?;
            return Ok(());
        } else {
            return Err(Error::InvalidSince);
        }
    } else {
        // pending HTLC unlock process
        // verify the unlock_htlc out of bound or not
        let pending_htlc_count = witness[0] as usize;
        let unlock_htlc = unlock_type as usize;
        if unlock_htlc >= pending_htlc_count {
            return Err(Error::InvalidUnlockType);
        }

        let raw_since_value = load_input_since(0, Source::GroupInput)?;
        let message = load_tx_hash()?;
        let mut signature = [0u8; 65];
        let mut pubkey_hash = [0u8; 20];

        let witness_len = witness.len();
        let pending_htlcs_len = 1 + pending_htlc_count * HTLC_SCRIPT_LEN;
        // verify the hash of the pending htlcs part is equal to the script args
        if blake2b_256(&witness[0..pending_htlcs_len])[0..20] != args[36..56] {
            return Err(Error::WitnessHashError);
        }
        if raw_since_value == 0 {
            let expected_witness_len = pending_htlcs_len + SIGNATURE_LEN + PREIMAGE_LEN;
            if witness_len != expected_witness_len {
                return Err(Error::WitnessLenError);
            }
            signature
                .copy_from_slice(&witness[pending_htlcs_len..pending_htlcs_len + SIGNATURE_LEN]);
        } else {
            let expected_witness_len = pending_htlcs_len + SIGNATURE_LEN;
            if witness_len != expected_witness_len {
                return Err(Error::WitnessLenError);
            }
            signature.copy_from_slice(&witness[pending_htlcs_len..]);
        }

        let mut new_amount = if type_script.is_some() {
            let input_cell_data = load_cell_data(0, Source::GroupInput)?;
            u128::from_le_bytes(input_cell_data[0..16].try_into().unwrap())
        } else {
            load_cell_capacity(0, Source::GroupInput)? as u128
        };
        let mut new_pending_htlcs: Vec<&[u8]> = Vec::new();
        let new_pending_htlc_count = [(pending_htlc_count - 1) as u8];
        new_pending_htlcs.push(&new_pending_htlc_count);

        for (i, htlc_script) in witness[1..pending_htlcs_len]
            .chunks(HTLC_SCRIPT_LEN)
            .enumerate()
        {
            let htlc = Htlc(htlc_script);
            if unlock_htlc == i {
                match htlc.htlc_type() {
                    HtlcType::Offered => {
                        if raw_since_value == 0 {
                            // when input since is 0, it means the unlock logic is for remote_htlc pubkey and preimage
                            let preimage = &witness[pending_htlcs_len + SIGNATURE_LEN..];
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
                            let preimage = &witness[pending_htlcs_len + SIGNATURE_LEN..];
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
                new_pending_htlcs.push(htlc_script);
            }
        }

        // verify the first output cell's lock script is correct
        let output_lock = load_cell_lock(0, Source::Output)?;
        let expected_lock_args = if new_pending_htlcs.len() == 1 {
            args[0..36].pack()
        } else {
            [
                &args[0..36],
                blake2b_256(new_pending_htlcs.concat())[0..20].as_ref(),
            ]
            .concat()
            .pack()
        };
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
