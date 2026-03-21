# Key Ceremony (Raspberry Pi)

Generates a new OPRF master key, prints admin shares, deploys node shares to TEE nodes, and verifies with a local OPRF simulation.

## Prepare the SD card

```
ceremony/
├── ceremony.sh              # main script
├── ceremony.env             # AWS creds + national ID (from ceremony.env.example)
├── config.env               # copy from deploy/config.env
├── nodes.json               # copy from deploy/nodes.json
├── toprf-keygen             # aarch64 binary
├── toprf-init-encrypt       # aarch64 binary
├── ssh-keys/
│   ├── toprf-node-1-key.pem
│   ├── toprf-node-2-key.pem
│   └── toprf-node-3-key.pem
└── coordinator-configs/
    ├── coordinator-node-1.json
    ├── coordinator-node-2.json
    └── coordinator-node-3.json
```

## Cross-compile binaries (on your Mac)

```bash
cd ~/threshold-oprf
cross build --release --target aarch64-unknown-linux-gnu -p toprf-keygen
cross build --release --target aarch64-unknown-linux-gnu -p toprf-seal --bin toprf-init-encrypt
```

Binaries are in `target/aarch64-unknown-linux-gnu/release/`.

## Install dependencies on the Pi

```bash
sudo apt install qrencode imagemagick jq awscli shred cups
```

Set up CUPS with the USB printer.

## Fill in ceremony.env

```
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=eu-west-1
NATIONALITY=Singapore
NATIONAL_ID=<your national ID>
```

## Run

```bash
./ceremony.sh
```

Resume from a specific step if something fails:

```bash
./ceremony.sh --from 7
```

## Steps

| Step | What happens | Network |
|------|-------------|---------|
| 1 | Generate 2-of-4 admin shares | Offline |
| 2 | Generate 2-of-3 node shares | Offline |
| 3 | Cross-verify both share sets reconstruct the same key | Offline |
| 4 | Connect to network | Manual |
| 5 | Configure AWS credentials | Online |
| 6 | Stop old nodes, init-seal with new key, start nodes | Online |
| 7 | Verify nodes healthy + correct group public key + e2e evaluate | Online |
| 8 | Shred node shares from disk | Online |
| 9 | Disconnect from network | Manual |
| 10 | Local OPRF simulation (hash_to_curve -> blind -> eval -> unblind -> ruonId) | Offline |
| 11 | Print admin shares (QR + plain text, one page each) | Offline |
| 12 | Shred admin shares from disk | Offline |
| 13 | Shred ceremony.env (AWS creds + national ID) | Offline |

## After the ceremony

1. Laminate the printed admin shares
2. Store in separate bank safe deposit boxes
3. Revoke/delete the IAM user used for the ceremony
4. Optionally run `deploy.sh lock` to remove SSH access (irreversible)
