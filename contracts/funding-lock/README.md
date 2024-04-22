# funding-lock

This is a simple funding lock script for ckb payment channel network. It utilizes the [ckb-auth] library to implement a 2-of-2 multi-sig script.

The lock script args is a blake160 hash of the aggregated public key of the two parties, to unlock this lock, the transaction must provide following fields in the witness:

- `version`: 8 bytes, u64 in little-endian
- `funding_out_point`: 36 bytes, out point of the funding transaction
- `pubkey`: 32 bytes, x only aggregated public key
- `signature`: 64 bytes, aggregated signature

To know more about the transaction building process, please refer to the `test_funding_lock` unit test.

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-auth]: https://github.com/nervosnetwork/ckb-auth
[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
