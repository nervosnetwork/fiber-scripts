`auth` is a binary built from the `ckb-auth` project. You may rebuild it by running following commands:

```bash
git clone https://github.com/nervosnetwork/ckb-auth.git
cd ckb-auth
git submodule update --init
make all-via-docker
cp build/auth ckb-pcn-scripts/deps
```

`simple_udt` is a binary built from the `ckb-production-scripts` project. You may rebuild it by running following commands:

```bash
git clone https://github.com/nervosnetwork/ckb-production-scripts.git
cd ckb-production-scripts
git submodule update --init --recursive
make all-via-docker
cp build/simple_udt ckb-pcn-scripts/deps
```
