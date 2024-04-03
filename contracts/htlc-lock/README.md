# htlc-lock

This is a simple HTLC lock script for ckb payment channel network.

The lock script args is concatenated by the following fields:

- `delay`: 8 bytes, the delay value of the HTLC, should be a relative timestamp, block number or epoch number
- `blake160(revocation_pubkey)`: 20 bytes
- `blake160(remote_htlc_pubkey)`: 20 bytes
- `blake160(local_htlc_pubkey)`: 20 bytes
- `payment_hash`: 20 bytes
- `expiry`: 8 bytes, an optional field to specify the expiry value of the HTLC, should be an absolute timestamp, block number or epoch number. If this field is present, the HTLC type is received, otherwise, the HTLC type is offered.

The witness is 65 bytes signature and an optional 32 bytes preimage of the payment hash, to know more about the transaction building process, please refer to the `test_htlc_lock_received` and `test_htlc_lock_offered` unit test.

TODO: Change to P2WSH style, change the lock script args to the hash of the witness script.

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
