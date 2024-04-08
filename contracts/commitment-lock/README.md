# commitment-lock

This is a simple commitment lock script for ckb payment channel network.

The lock script args is the hash result of blake160(to_self_delay || local_delayed_pubkey_hash || revocation_pubkey_hash), the witness is concatenated by the following fields:

- to_self_delay: 8 bytes, u64 in little endian, the delay time for the to_self output
- local_delayed_pubkey_hash: 20 bytes, hash result of blake160(local_delayed_pubkey)
- revocation_pubkey_hash: 20 bytes, hash result of blake160(revocation_pubkey)
- signature: 65 bytes, the signature of the local_delayed_pubkey or revocation_pubkey

To know more about the transaction building process, please refer to the `test_commitment_lock` unit test.

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
