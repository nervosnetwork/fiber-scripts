# htlc-lock

This is a simple HTLC lock script for ckb payment channel network.

The lock script args is the hash result of blake160(delay || revocation_pubkey_hash || remote_htlc_pubkey_hash || local_htlc_pubkey_hash || payment_hash || expiry), the witness is concatenated by the following fields:

- `delay`: 8 bytes, the delay value of the HTLC, should be a relative timestamp, block number or epoch number
- `revocation_pubkey_hash`: 20 bytes, the hash of blake160(revocation_pubkey)
- `remote_htlc_pubkey_hash`: 20 bytes, the hash of blake160(remote_htlc_pubkey)
- `local_htlc_pubkey_hash`: 20 bytes, the hash of blake160(local_htlc_pubkey)
- `payment_hash`: 20 bytes
- `expiry`: 8 bytes, an optional field to specify the expiry value of the HTLC, should be an absolute timestamp, block number or epoch number. If this field is present, the HTLC type is received, otherwise, the HTLC type is offered.
- `signature`: 65 bytes
- `preimage`: 32 bytes, an optional field to provide the preimage of the payment_hash

To know more about the transaction building process, please refer to the `test_htlc_lock_received` and `test_htlc_lock_offered` unit test.

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
