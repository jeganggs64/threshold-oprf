# Key Ceremony (Raspberry Pi)

Generates a new OPRF master key, deploys node shares to TEE nodes, verifies with local + mobile OPRF evaluation, and encrypts the master key with `age`.

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
sudo apt install jq awscli age shred
```

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
| 4 | Connect to network + configure AWS | Manual → Online |
| 5 | Deploy key shares to nodes (init-seal + start) | Online |
| 6 | Verify nodes healthy + correct group public key + e2e evaluate | Online |
| 7 | Shred node shares from disk | Online |
| 8 | Disconnect from network | Manual |
| 9 | Local OPRF simulation + mobile app verification | Offline |
| 10 | Encrypt admin shares with `age` passphrase → `key.age`, shred all plaintext | Offline |

## After the ceremony

1. Power off the Pi
2. Plug SD card into your Mac
3. Copy `key.age` to iCloud / secure backup
4. Securely wipe the SD card: `sudo dd if=/dev/zero of=/dev/mmcblk0 bs=4M status=progress`
5. Revoke/delete the IAM user used for the ceremony

## Decrypting the key (if needed)

```bash
age -d key.age > admin-shares.json
```

Enter the 6-word diceware passphrase you chose during the ceremony.
