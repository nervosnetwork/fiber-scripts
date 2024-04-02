# commitment-lock

This is a simple commitment lock script for ckb payment channel network.

The lock script args is concatenated by the to_self_delay || blake160(local_delayed_pubkey) || blake160(revocation_pubkey), to know more about the transaction building process, please refer to the `test_commitment_lock` unit test.

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
