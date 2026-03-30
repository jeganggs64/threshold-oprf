# RuonID — Passport-Based Sybil Resistance Without a Biometric Database

## What it does

RuonID lets any app verify that a user is a unique real person, using only their existing government passport. No custom hardware, no biometric database, no trusted operator. The user gets a deterministic pseudonymous ID that is unlinkable across apps.

## How it works

```
User's phone                          OPRF Nodes (2-of-3, AMD SEV-SNP)
─────────────                         ─────────────────────────────────
1. NFC-read passport chip
2. Verify passport signature (CSCA)
3. Face match: live camera vs
   passport photo (ArcFace, on-device)
4. Blind(nationality ∥ documentNumber)
   ──── blinded point ──────────────→  5. Each node computes partial
                                          OPRF evaluation on its key share
                                       6. DLEQ proofs attached
   ←── partial evaluations ─────────
7. Verify DLEQ proofs
8. Combine + unblind
9. ruonId = keccak256(OPRF output)
```

**The server never sees the passport data. The client never sees the key.**

Same passport → same `ruonId` every time (sybil resistance). Different apps receive `SHA256(ruonId ∥ developerId)` — deterministic but unlinkable across apps.

## Security model

| Layer | Guarantee |
|-------|-----------|
| **Key custody** | Master key is split via Shamir (2-of-3). Each share is sealed to AMD SEV-SNP hardware via `MSG_KEY_REQ`. No human — including the operator — can extract a share. |
| **Node compromise** | Threshold scheme requires 2 nodes to collude. Each node has independent attestation and hardware-sealed key shares. |
| **Node rotation** | Reshare protocol replaces a node's share without changing the master key. New share is sealed to fresh hardware, verified via SNP attestation before any key material is transmitted. |
| **Passport verification** | Passive authentication: RSA/ECDSA signature on chip data verified against ICAO CSCA master list. Detects cloned/forged passports. |
| **Biometric** | ArcFace face embedding (ONNX, on-device). Passport photo vs live camera. 5-point landmark alignment, CLAHE preprocessing. Embedding never leaves the device. |
| **Device integrity** | iOS App Attest / Android Play Integrity. Server verifies attestation before issuing a receipt. Prevents emulators and modified apps. |
| **Replay** | OPRF input is blinded with a fresh random scalar per request. The blinding factor never leaves the client. |

## What integrators receive

A developer registers and gets a secp256k1 keypair. To verify a user:

1. Generate a signed QR code or deeplink containing a session ID, callback URL, and signature.
2. User scans it in RuonID → sees a consent screen → authenticates with biometrics.
3. RuonID POSTs to the callback URL:

```json
{
  "appSpecificId": "0x...",    // SHA256(ruonId ∥ developerId) — unique per user per app
  "identityTier": "passport-bound",
  "deviceVerified": true,
  "timestamp": "2026-03-30T...",
  "receipt": { ... }           // server-signed attestation, verifiable with SDK
}
```

The `appSpecificId` is deterministic — same user always produces the same ID for the same app. Different apps get different IDs. No PII is transmitted.

**For apps that need PII** (KYC): a separate identity flow sends ECIES-encrypted passport fields (name, DOB, nationality, etc.) encrypted to the developer's public key. The user explicitly consents to each field.

## Why a server-side key is necessary

Deterministic sybil resistance requires that the same person always produces the same ID. This means the output must be a function of (1) the person's identity data and (2) nothing else that varies. We show that a server-side secret is unavoidable for this to work securely.

**Claim:** A deterministic, sybil-resistant identity scheme cannot be fully client-side.

**Proof by cases:**

*Case 1: Client-only, no secret.* The function is `ID = f(passport_data)`. Since `f` is public and `passport_data` is readable from any passport, anyone with access to a passport can compute the ID for its holder — including the passport holder's employer, border agent, or an attacker who momentarily holds the document. The ID has no authentication; it's just a hash of public data. Sybil resistance fails because there is no proof that the person computing the ID is the person on the passport.

*Case 2: Client-only, with a client secret.* The function is `ID = f(passport_data, client_secret)`. This authenticates the computation, but the `client_secret` is device-bound. If the user loses their phone, gets a new device, or reinstalls the app, `client_secret` changes. The ID is no longer deterministic — the same person produces different IDs on different devices. Sybil resistance fails because there is no way to link the old and new IDs.

*Case 3: Server-side secret.* The function is `ID = f(passport_data, server_key)`. The `server_key` is persistent and independent of the user's device. The same `passport_data` always produces the same ID regardless of which device the user uses. The computation is authenticated because only the server can evaluate `f` with its key. **This is the only case that satisfies both determinism and authentication.**

**The privacy problem with Case 3:** If the server sees `passport_data` in the clear, it learns the user's identity. This is where the OPRF comes in. The client blinds the input before sending it, the server evaluates the function on the blinded input, and the client unblinds the result. The server never sees the raw input; the client never sees the key. The output is identical to Case 3 but with no privacy loss.

**The trust problem with Case 3:** A single server holding the key is a central point of failure. This is where threshold cryptography comes in. The key is split across multiple independent nodes (2-of-3), each sealed to hardware (AMD SEV-SNP). No single node — and no operator — can extract the key or compute IDs independently.

**Summary:** Determinism requires a persistent secret. Device-bound secrets break determinism. Therefore the secret must live server-side. OPRF eliminates the privacy cost. Threshold splitting eliminates the trust cost. The result is a scheme that is deterministic, privacy-preserving, and trust-minimized — but not fully decentralized, because the server-side key is fundamental to the construction.

## Why not just use World ID / other solutions?

| | RuonID | World ID | Government eID |
|---|--------|----------|-----------------|
| **Hardware required** | Any NFC phone + existing passport | Orb (custom iris scanner) | Country-specific readers |
| **Biometric storage** | None (on-device only) | Iris hash stored on-chain | Varies by country |
| **Trusted operator** | None (threshold OPRF in TEEs) | Worldcoin Foundation | Government |
| **Coverage** | 150+ countries (ICAO ePassports) | Orb locations only | Single country |
| **Credential type** | ePassport (NFC chip, PKI-signed) | Iris biometric | National ID card |
| **Sybil resistance** | Deterministic OPRF output | Iris uniqueness | Government-issued uniqueness |
| **Cross-app linkability** | Unlinkable (app-specific IDs) | Unlinkable | Typically linkable |

## Integration

- **SDK**: `npm install @ruonid/sdk` — verify receipts server-side
- **No server infrastructure needed** — just generate QR codes and handle the callback POST
- **Two tiers**: sybil-only (free, just `appSpecificId`) and identity (paid, encrypted PII fields)
- **API docs**: https://ruonlabs.com/developers

## Open questions for partners

- What attestation format do you need? We currently provide a server-signed JSON receipt with device attestation binding. Happy to adapt to on-chain proof formats.
- Do you need the sybil tier (unique user check only) or the identity tier (verified PII)?
- What's your callback infrastructure? We POST to any HTTPS endpoint you control.
