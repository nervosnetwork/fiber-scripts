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
        exec_cell, load_cell_capacity, load_cell_lock, load_input_since, load_script, load_tx_hash,
        load_witness,
    },
    since::Since,
};
use hex::encode;

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
    WitnessHashError,
    OutputCapacityError,
    OutputLockError,
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

// min witness script length: 8 (local_delay_epoch) + 20 (local_delay_pubkey_hash) + 20 (revocation_pubkey_hash) = 48
const MIN_WITNESS_SCRIPT_LEN: usize = 48;
// HTLC script length: 1 (htlc_type) + 8 (payment_amount) + 20 (payment_hash) + 20 (remote_htlc_pubkey_hash) + 20 (local_htlc_pubkey_hash) + 8 (htlc_expiry) = 77
const HTLC_SCRIPT_LEN: usize = 77;
// 1 (unlock_type) + 65 (signature) = 66
const UNLOCK_WITH_SIGNATURE_LEN: usize = 66;
const PREIMAGE_LEN: usize = 32;
const MIN_WITNESS_LEN: usize = MIN_WITNESS_SCRIPT_LEN + UNLOCK_WITH_SIGNATURE_LEN;

fn auth() -> Result<(), Error> {
    // since local_delay_pubkey and revocation_pubkey are derived, the scripts are usually unique,
    // to simplify the implementation of the following unlocking logic, we check the number of inputs should be 1
    if load_input_since(1, Source::GroupInput).is_ok() {
        return Err(Error::MultipleInputs);
    }

    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    if args.len() != 20 {
        return Err(Error::ArgsLenError);
    }
    let witness = load_witness(0, Source::GroupInput)?;
    let witness_len = witness.len();
    if witness_len < MIN_WITNESS_LEN {
        return Err(Error::WitnessLenError);
    }
    let (pending_htlcs, preimage) = match witness_len {
        MIN_WITNESS_LEN => (0, None),
        _ => match (witness_len - MIN_WITNESS_LEN) % HTLC_SCRIPT_LEN {
            0 => ((witness_len - MIN_WITNESS_LEN) / HTLC_SCRIPT_LEN, None),
            PREIMAGE_LEN => (
                (witness_len - PREIMAGE_LEN - MIN_WITNESS_LEN) / HTLC_SCRIPT_LEN,
                Some(&witness[witness_len - PREIMAGE_LEN..]),
            ),
            _ => return Err(Error::WitnessLenError),
        },
    };

    // verify the hash of the witness script part is equal to the script args
    let witness_script_len = witness_len
        - if preimage.is_some() {
            UNLOCK_WITH_SIGNATURE_LEN + PREIMAGE_LEN
        } else {
            UNLOCK_WITH_SIGNATURE_LEN
        };
    if blake2b_256(&witness[0..witness_script_len])[0..20] != args[0..20] {
        return Err(Error::WitnessHashError);
    }

    let unlock_type = witness[witness_script_len];
    let signature = witness[witness_script_len + 1..witness_script_len + 66].to_vec();

    let message = load_tx_hash()?;
    let mut pubkey_hash = [0u8; 20];

    if unlock_type == 0xFF {
        // unlock with revocation or local_delay pubkey
        let raw_since_value = load_input_since(0, Source::GroupInput)?;
        if raw_since_value == 0 {
            // when input since is 0, it means the unlock logic is for revocation, verify the revocation pubkey
            pubkey_hash.copy_from_slice(&witness[28..48]);
        } else {
            // when input since is not 0, it means the unlock logic is for local_delay, verify the local_delay pubkey and delay
            let since = Since::new(raw_since_value);
            let local_delay_epoch =
                Since::new(u64::from_le_bytes(witness[0..8].try_into().unwrap()));
            if since >= local_delay_epoch {
                pubkey_hash.copy_from_slice(&witness[8..28]);
            } else {
                return Err(Error::InvalidSince);
            }
        }
    } else {
        let unlock_htlc = unlock_type as usize;
        if unlock_htlc >= pending_htlcs {
            return Err(Error::InvalidUnlockType);
        }

        let mut new_capacity = load_cell_capacity(0, Source::GroupInput)?;
        let mut new_witness_script: Vec<&[u8]> = Vec::new();
        new_witness_script.push(&witness[0..MIN_WITNESS_SCRIPT_LEN]);

        for (i, htlc) in witness[MIN_WITNESS_SCRIPT_LEN..witness_script_len]
            .chunks(HTLC_SCRIPT_LEN)
            .enumerate()
        {
            if unlock_htlc == i {
                if htlc[0] == 0 {
                    // offered HTLC
                    let raw_since_value = load_input_since(0, Source::GroupInput)?;
                    if raw_since_value == 0 {
                        // when input since is 0, it means the unlock logic is for remote_htlc pubkey and preimage
                        if preimage
                            .map(|p| blake2b_256(p)[0..20] != htlc[9..29])
                            .unwrap_or(false)
                        {
                            return Err(Error::PreimageError);
                        }
                        new_capacity -= u64::from_le_bytes(htlc[1..9].try_into().unwrap());
                        pubkey_hash.copy_from_slice(&htlc[29..49]);
                    } else {
                        // when input since is not 0, it means the unlock logic is for local_htlc pubkey and htlc expiry
                        let since = Since::new(raw_since_value);
                        let htlc_expiry =
                            Since::new(u64::from_le_bytes(htlc[69..77].try_into().unwrap()));
                        if since >= htlc_expiry {
                            pubkey_hash.copy_from_slice(&htlc[49..69]);
                        } else {
                            return Err(Error::InvalidSince);
                        }
                    }
                } else if htlc[0] == 1 {
                    // received HTLC
                    let raw_since_value = load_input_since(0, Source::GroupInput)?;
                    if raw_since_value == 0 {
                        // when input since is 0, it means the unlock logic is for local_htlc pubkey and preimage
                        if preimage
                            .map(|p| blake2b_256(p)[0..20] != htlc[9..29])
                            .unwrap_or(false)
                        {
                            return Err(Error::PreimageError);
                        }
                        pubkey_hash.copy_from_slice(&htlc[49..69]);
                    } else {
                        // when input since is not 0, it means the unlock logic is for remote_htlc pubkey and htlc expiry
                        let since = Since::new(raw_since_value);
                        let htlc_expiry =
                            Since::new(u64::from_le_bytes(htlc[69..77].try_into().unwrap()));
                        if since >= htlc_expiry {
                            new_capacity -= u64::from_le_bytes(htlc[1..9].try_into().unwrap());
                            pubkey_hash.copy_from_slice(&htlc[29..49]);
                        } else {
                            return Err(Error::InvalidSince);
                        }
                    }
                } else {
                    return Err(Error::InvalidHtlcType);
                }
            } else {
                new_witness_script.push(htlc);
            }
        }
        // verify the first output cell's capacity and lock is correct
        let output_capacity = load_cell_capacity(0, Source::Output)?;
        if output_capacity != new_capacity {
            return Err(Error::OutputCapacityError);
        }

        let output_lock = load_cell_lock(0, Source::Output)?;
        let expected_lock_args = blake2b_256(new_witness_script.concat())[0..20].pack();
        if output_lock.code_hash() != script.code_hash()
            || output_lock.hash_type() != script.hash_type()
            || output_lock.args() != expected_lock_args
        {
            return Err(Error::OutputLockError);
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
