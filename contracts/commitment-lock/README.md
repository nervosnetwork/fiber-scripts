# commitment-lock

This is a commitment lock script for ckb fiber network, which implements [daric] protocol.

## Lock Script Args and Witness Structure
The lock script args is concatenated by the following fields:

- `pubkey_hash`: 20 bytes, hash result of blake160(x only aggregated public key)
- `delay_epoch`: 8 bytes, u64 in little endian, must be a relative [EpochNumberWithFraction](https://github.com/nervosnetwork/ckb/blob/develop/rpc/README.md#type-epochnumberwithfraction)
- `version`: 8 bytes, u64 in big-endian
- `settlement_hash`: 20 bytes, hash result of blake160(pending_htlc_count || N * pending_htlc || settlement_remote_pubkey_hash || settlement_remote_amount || settlement_local_pubkey_hash || settlement_local_amount)
- `settlement_flag`: 1 byte, 0x00 means this cell is created for first funding cell unlock, 0x01 means this cell is created for subsequent commitment cell unlock, others are reserved

To unlock this lock, the transaction must provide the following fields in the witness:
- `empty_witness_args`: 16 bytes, fixed to 0x10000000100000001000000010000000, for compatibility with the xudt
- `unlock_count`: 1 byte, 0x00 for revocation unlock, 0x01 ~ 0xFF for settlement unlocks count.

For revocation unlock process, the transaction must provide the following fields in the witness:
- `version`: 8 bytes, u64 in big-endian, must be the same or greater than the version in the lock args
- `pubkey`: 32 bytes, x only aggregated public key
- `signature`: 64 bytes, aggregated signature

For settlement unlock process, the transaction must provide the following fields in the witness:
- `pending_htlc_count`: 1 byte, the count of pending HTLCs
- `pending_htlc`: A group of pending HTLCS, each HTLC is 85 bytes, contains:
    - `htlc_type`: 1 byte, high 7 bits for payment hash type (0000000 for blake2b, 0000001 for sha256), low 1 bit for offered or received type (0 for offered HTLC, 1 for received HTLC)
    - `payment_amount`: 16 bytes, u128 in little endian
    - `payment_hash`: 20 bytes
    - `remote_htlc_pubkey_hash`: 20 bytes, hash result of blake160(remote_htlc_pubkey)
    - `local_htlc_pubkey_hash`: 20 bytes, hash result of blake160(local_htlc_pubkey)
    - `htlc_expiry`: 8 bytes, u64 in little endian, must be an absolute timestamp [since](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md)
- `settlement_remote_pubkey_hash`: 20 bytes, hash result of blake160(pubkey)
- `settlement_remote_amount`: 16 bytes, u128 in little endian
- `settlement_local_pubkey_hash`: 20 bytes, hash result of blake160(pubkey)
- `settlement_local_amount`: 16 bytes, u128 in little endian

- `unlocks`: A group of settlement unlock signature and preimage
    - `unlock_type`: 0x00 ~ 0xFD for pending htlc group index, 0xFE for settlement remote, 0xFF for settlement local.
    - `with_preimage`: 0x00 without preimage, 0x01 with preimage
    - `signature`: 65 bytes, the signature of the xxx_pubkey
    - `preimage`: 32 bytes, an optional field to provide the preimage of the payment_hash

## Settlement Unlock Process and New Lock Script Args Generation

During the settlement unlock process, when HTLCs are settled or parties claim their funds, a new output cell with updated lock script args is generated. The new lock script args follow the same structure but with updated `settlement_hash`:

### New Settlement Script Generation

The new settlement script is constructed by:

1. **Updated pending HTLCs**: Remove settled HTLCs from the original list
   - `new_pending_htlc_count`: Decremented count after settling HTLCs
   - Remaining unsettled HTLCs in the same 85-byte format

2. **Updated settlement amounts**: Adjust party amounts based on settlements
   - For remote settlement (unlock_type = 0xFE): Set settlement_local_amount to 0 and pubkey hash to 20 bytes zeros
   - For local settlement (unlock_type = 0xFF): Set settlement_remote_amount to 0 and pubkey hash to 20 bytes zeros
   - For HTLC settlements: Deduct payment amounts from total available funds

### New Lock Script Args Construction

The new lock script args are generated as:
```
new_args = [
    pubkey_hash,           // Same as original (20 bytes)
    delay_epoch,           // Same as original (8 bytes)
    version,               // Same as original (8 bytes)
    new_settlement_hash    // Updated hash (20 bytes)
]
```

Where `new_settlement_hash = blake2b_256(new_settlement_script)[0..20]`

### Examples from Tests

1. **Local Settlement**: When local party settles, their settlement amount becomes 0 and pubkey hash is updated to 20 bytes zeros:
   ```rust
   new_settlement_script = [
       new_pending_htlc_count,
       remaining_htlcs...,
       remote_pubkey_hash,
       remaining_remote_amount.to_le_bytes(),
       [0u8; 20],               // Local pubkey hash set to 20 bytes zeros
       0u128.to_le_bytes(),     // Local amount set to 0
   ]
   ```

2. **HTLC Settlement**: When HTLCs are settled, they're removed from pending list:
   ```rust
   new_settlement_script = [
       (original_count - settled_count),
       unsettled_htlcs...,
       settlement_party_data...
   ]
   ```

3. **Batch Settlement**: Multiple HTLCs and party settlements can be processed together, with all changes reflected in the new settlement script.

The verification logic ensures that:
- The new lock script uses the same code_hash and hash_type
- The new args match the expected format with updated settlement_hash
- Output capacity/UDT amount reflects the settled amounts correctly

## Congestion Attack Prevention

This contract includes protection against congestion attacks. A congestion attack works as follows:

1. Alice sends a TLC A to Bob (Bob knows the preimage)
2. Alice sends many TLCs that are going to expire soon
3. Alice shuts down the channel
4. Bob needs to use the preimage to settle TLC A, but Alice can create settlement transactions to claim the expired TLCs first

Without protection, Alice could flood Bob with many soon-to-expire TLCs and then close the channel. This forces Bob to compete with Alice to settle TLC A with his preimage, while Alice races to claim all her expired TLCs.

### Solution

The contract requires proving that **all pending HTLCs have expired** before claiming any expired HTLC without preimage. This is enforced by checking that the `since` value (absolute timestamp) is greater than or equal to the maximum expiry time of all pending HTLCs.

- **Preimage-based unlocks** (with_preimage = 1): Can be executed at any time (after the delay epoch) and are not affected by this check. This ensures Bob can always claim TLCs for which he knows the preimage.
- **Expiry-based unlocks** (with_preimage = 0): Require that all pending HTLCs have expired. This prevents Alice from claiming her expired TLCs before Bob has a chance to claim TLCs with preimage.

To know more about the transaction building process, please refer to the `test_commitment_lock_*` unit test.

*This contract was bootstrapped with [ckb-script-templates].*

[daric]: https://eprint.iacr.org/2022/1295
[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
