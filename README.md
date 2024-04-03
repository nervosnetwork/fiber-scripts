# CKB Payment Channel Network Scripts

This repository contains the scripts for the CKB Payment Channel Network.

- [funding-lock](contracts/funding-lock/README.md)

- [commitment-lock](contracts/commitment-lock/README.md)

- [htlc-lock](contracts/htlc-lock/README.md)

A chart of the payment channel network transaction is shown below:
```

   ┌──────────┐
   │funding tx│
   └────┬─────┘
        │       ┌───────────────┐
        └──────►│commitment tx B│
                └─┬────┬───┬───┬┘
                  │    │   │   │  A's main output
                  │    │   │   └─────────────────► to A
                  │    │   │
                  │    │   │
                  │    │   │                   ┌─► to B after delay
                  │    │   │  B's main output  │
                  │    │   └───────────────────┤
                  │    │                       │
                  │    │                       └─► to A by revocation
                  │    │
                  │    │
                  │    │                       ┌─► to B after delay (plus timeout)
                  │    │                       │
                  │    │  HTLCs offered by B   │
                  │    └───────────────────────┼─► to A by revocation
                  │                            │
                  │                            │
                  │                            └─► to A with preimage
                  │
                  │
                  │                            ┌─► to B after delay (with preimage)
                  │                            │
                  │  HTLCs received by B       │
                  └────────────────────────────┼─► to A by revocation
                                               │
                                               │
                                               └─► to A after timeout

```

## How to build and test

```
make build
make test
```

*This workspace was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/cryptape/ckb-script-templates
