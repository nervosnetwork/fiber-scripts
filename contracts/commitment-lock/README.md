# commitment-lock

This is a commitment lock script for ckb fiber network, which implements [daric] protocol.

The lock script args is concatenated by the following fields:

- `pubkey_hash`: 20 bytes, hash result of blake160(x only aggregated public key)
- `delay_epoch`: 8 bytes, u64 in little endian, must be a relative EpochNumberWithFraction
- `version`: 8 bytes, u64 in big-endian
- `htlcs`: 20 bytes, hash result of blake160(pending_htlc_count || N * pending_htlc), optional

To unlock this lock, the transaction must provide the following fields in the witness:
- `empty_witness_args`: 16 bytes, fixed to 0x10000000100000001000000010000000, for compatibility with the xudt
- `unlock_type`: 1 byte, 0x00 ~ 0xFD for pending HTLC unlock, 0xFE for non-pending HTLC unlock, 0xFF for revocation unlock

For revocation unlock process, the transaction must provide the following fields in the witness:
- `version`: 8 bytes, u64 in big-endian, must be the same or greater than the version in the lock args
- `pubkey`: 32 bytes, x only aggregated public key
- `signature`: 64 bytes, aggregated signature

For non-pending HTLC unlock process, the transaction must provide the following fields in the witness:
- `pubkey`: 32 bytes, x only aggregated public key
- `signature`: 64 bytes, aggregated signature

For pending HTLC unlock process, the transaction must provide the following fields in the witness:
- `pending_htlc_count`: 1 byte, the count of pending HTLCs
- `pending_htlc`: A group of pending HTLCS, each HTLC is 85 bytes, contains:
    - `htlc_type`: 1 byte, high 7 bits for payment hash type (0000000 for blake2b, 0000001 for sha256), low 1 bit for offered or received type (0 for offered HTLC, 1 for received HTLC)
    - `payment_amount`: 16 bytes, u128 in little endian
    - `payment_hash`: 20 bytes
    - `local_htlc_pubkey_hash`: 20 bytes, hash result of blake160(local_htlc_pubkey)
    - `remote_htlc_pubkey_hash`: 20 bytes, hash result of blake160(remote_htlc_pubkey)
    - `htlc_expiry`: 8 bytes, u64 in little endian, must be an absolute timestamp
- `signature`: 65 bytes, the signature of the xxx_pubkey
- `preimage`: 32 bytes, an optional field to provide the preimage of the payment_hash

To know more about the transaction building process, please refer to the `test_commitment_lock_*` unit test.

*This contract was bootstrapped with [ckb-script-templates].*

[daric]: https://eprint.iacr.org/2022/1295
[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
