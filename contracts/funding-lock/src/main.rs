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

use alloc::ffi::CString;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    error::SysError,
    high_level::{
        exec_cell, load_input_out_point, load_input_since, load_script, load_tx_hash, load_witness,
    },
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
    WitnessLenError,
    FundingOutPointError,
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

fn auth() -> Result<(), Error> {
    // funding lock will be unlocked by the commitment transaction, it should only have one input
    if load_input_since(1, Source::GroupInput).is_ok() {
        return Err(Error::MultipleInputs);
    }
    let witness = load_witness(0, Source::GroupInput)?;
    if witness.len() != 8 + 36 + 32 + 64 {
        return Err(Error::WitnessLenError);
    }
    let tx_hash = load_tx_hash()?;
    let version = witness[0..8].to_vec();
    let funding_out_point = witness[8..44].to_vec();
    let input_out_point = load_input_out_point(0, Source::GroupInput)?;
    if input_out_point.as_slice() != funding_out_point.as_slice() {
        return Err(Error::FundingOutPointError);
    }
    // Schnorr signature cannot recover the public key, so we need to provide the public key
    let pubkey_and_signature = witness[44..].to_vec();
    let message = blake2b_256([version, funding_out_point, tx_hash.to_vec()].concat());

    let mut pubkey_hash = [0u8; 20];
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    pubkey_hash.copy_from_slice(&args[0..20]);

    // AuthAlgorithmIdSchnorr = 7
    let algorithm_id_str = CString::new(encode([7u8])).unwrap();
    let signature_str = CString::new(encode(pubkey_and_signature)).unwrap();
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
