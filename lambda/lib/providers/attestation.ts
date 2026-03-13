import { createHash, createHmac, verify as cryptoVerify } from "crypto";
import { DeviceKeyStore } from "../stores/deviceKeys";

/** Interface for device attestation providers. */
export interface AttestationProvider {
  /**
   * Verify a device attestation token.
   * Returns the deviceId on success, throws on failure.
   */
  verify(token: string, nonce: string): Promise<string>;
}

/** Extended interface for providers that support one-time key registration (Apple). */
export interface AttestableProvider extends AttestationProvider {
  /**
   * Register a device key via attestation (Apple App Attest one-time registration).
   * Returns the deviceId (keyId) on success, throws on failure.
   */
  attest(attestationObjectB64: string, keyId: string, challenge: string): Promise<string>;
}

// ---------------------------------------------------------------------------
// Apple App Attest Root CA (production)
// ---------------------------------------------------------------------------

const APPLE_APP_ATTEST_ROOT_CA_PROD = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

// OID for Apple App Attest nonce: 1.2.840.113635.100.8.2
const APPLE_ATTEST_NONCE_OID = "1.2.840.113635.100.8.2";

/**
 * Apple App Attest provider.
 *
 * Two-phase model:
 * 1. attest() — one-time key registration (validates CBOR attestation object)
 * 2. verify() — per-request assertion (validates signature with stored key)
 */
export class AppleAppAttestProvider implements AttestableProvider {
  constructor(
    private appId: string,
    private teamId: string,
    private keyStore: DeviceKeyStore,
  ) {}

  /**
   * One-time key registration.
   * Validates the CBOR attestation object from Apple's Secure Enclave.
   */
  async attest(
    attestationObjectB64: string,
    keyId: string,
    challenge: string
  ): Promise<string> {
    // Dynamically import cbor and x509 (optional deps)
    const cbor = await import("cbor");
    const x509 = await import("@peculiar/x509");

    // 1. Base64-decode and CBOR-decode the attestation object
    const attestationBuffer = Buffer.from(attestationObjectB64, "base64");
    const attestationObject = cbor.decodeFirstSync(attestationBuffer);

    const { fmt, attStmt, authData } = attestationObject;
    if (fmt !== "apple-appattest") {
      throw new Error(`Unexpected attestation format: ${fmt}`);
    }

    // 1a. Verify rpIdHash — first 32 bytes of authData must equal SHA256(appId)
    const expectedRpIdHash = createHash("sha256").update(this.appId).digest();
    const rpIdHash = Buffer.from(authData).subarray(0, 32);
    if (!expectedRpIdHash.equals(rpIdHash)) {
      throw new Error("Attestation rpIdHash does not match expected App ID");
    }

    // 2. Extract x5c certificate chain
    const x5c: Buffer[] = attStmt.x5c;
    if (!x5c || x5c.length < 2) {
      throw new Error("Attestation missing x5c certificate chain");
    }

    // Parse the credential cert (leaf) and intermediate
    const credCert = new x509.X509Certificate(x5c[0]);

    // 3. Verify cert chain leads to Apple's root CA
    const rootPem = APPLE_APP_ATTEST_ROOT_CA_PROD;

    const rootCert = new x509.X509Certificate(rootPem);
    const chain = new x509.X509ChainBuilder({ certificates: x5c.slice(1).map((c) => new x509.X509Certificate(c)) });

    const builtChain = await chain.build(credCert);
    // Verify the last cert in the chain is issued by Apple root
    const lastCert = builtChain[builtChain.length - 1];
    if (!lastCert) {
      throw new Error("Failed to build certificate chain");
    }

    // Verify root CA issuer matches (structural check)
    if (lastCert.issuer !== rootCert.subject) {
      throw new Error("Certificate chain does not lead to Apple root CA");
    }

    // Cryptographic signature verification of the certificate chain.
    const allCerts = [...builtChain];
    for (let i = 0; i < allCerts.length; i++) {
      const issuerCert = i < allCerts.length - 1 ? allCerts[i + 1] : rootCert;
      const isValid = await allCerts[i].verify({
        publicKey: issuerCert.publicKey,
        signatureOnly: true,
      });
      if (!isValid) {
        throw new Error(`Certificate chain signature verification failed at depth ${i}`);
      }
    }

    // 4. Verify nonce: SHA256(authData || clientDataHash) must match the OID extension value
    const clientDataHash = createHash("sha256").update(challenge).digest();
    const expectedNonce = createHash("sha256")
      .update(Buffer.concat([Buffer.from(authData), clientDataHash]))
      .digest();

    // Extract the nonce from the credential cert's extension
    const nonceExt = credCert.getExtension(APPLE_ATTEST_NONCE_OID);
    if (!nonceExt) {
      throw new Error("Attestation cert missing nonce extension");
    }

    const extValue = Buffer.from(nonceExt.value);
    const nonceFromCert = extValue.subarray(extValue.length - 32);

    if (!expectedNonce.equals(nonceFromCert)) {
      throw new Error("Attestation nonce mismatch");
    }

    // 5. Verify SHA256(credCert.publicKey) matches the provided keyId
    const pubKeyHash = createHash("sha256")
      .update(Buffer.from(credCert.publicKey.rawData))
      .digest("base64url");

    const keyIdNormalized = Buffer.from(keyId, "base64").toString("base64url");
    if (pubKeyHash !== keyIdNormalized && pubKeyHash !== keyId) {
      const credentialId = this.extractCredentialId(authData);
      const credIdB64 = Buffer.from(credentialId).toString("base64url");
      if (credIdB64 !== keyIdNormalized && credIdB64 !== keyId) {
        throw new Error("Key ID does not match credential certificate");
      }
    }

    // 6. Extract EC public key PEM from the leaf cert
    const publicKeyPem = credCert.publicKey.toString("pem");

    // 7. Store the key
    await this.keyStore.saveKey(keyId, publicKeyPem, 0);

    return keyId;
  }

  /**
   * Per-request assertion verification.
   * Validates the signature generated by the Secure Enclave.
   */
  async verify(assertionB64: string, nonce: string): Promise<string> {
    let parsed: { keyId: string; assertion?: string; authenticatorData?: string; signature?: string };
    try {
      parsed = JSON.parse(Buffer.from(assertionB64, "base64").toString("utf8"));
    } catch {
      throw new Error("Invalid assertion token format");
    }

    const { keyId } = parsed;
    if (!keyId) {
      throw new Error("Assertion missing required fields (keyId)");
    }

    let authDataBuf: Buffer;
    let signatureBuf: Buffer;

    if (parsed.assertion) {
      const cbor = await import("cbor");
      const assertionBuf = Buffer.from(parsed.assertion, "base64");
      const decoded = cbor.decodeFirstSync(assertionBuf);
      authDataBuf = Buffer.from(decoded.authenticatorData);
      signatureBuf = Buffer.from(decoded.signature);
    } else if (parsed.authenticatorData && parsed.signature) {
      authDataBuf = Buffer.from(parsed.authenticatorData, "base64");
      signatureBuf = Buffer.from(parsed.signature, "base64");
    } else {
      throw new Error("Assertion missing required fields (assertion or authenticatorData+signature)");
    }

    // 1. Look up stored public key
    const entry = await this.keyStore.getKey(keyId);
    if (!entry) {
      throw new Error(`Unknown device key: ${keyId}`);
    }

    // 2. Verify rpIdHash
    if (authDataBuf.length >= 32) {
      const expectedRpIdHash = createHash("sha256").update(this.appId).digest();
      const rpIdHash = authDataBuf.subarray(0, 32);
      if (!expectedRpIdHash.equals(rpIdHash)) {
        throw new Error("Assertion rpIdHash does not match expected App ID");
      }
    }

    // 3. Compute clientDataHash = SHA256(nonce)
    const clientDataHash = createHash("sha256").update(nonce).digest();

    // 4. Compute composite hash: SHA256(authenticatorData || clientDataHash)
    const composite = Buffer.concat([authDataBuf, clientDataHash]);
    const compositeHash = createHash("sha256").update(composite).digest();

    // 5. Verify the raw ECDSA signature
    const valid = cryptoVerify(
      null, compositeHash,
      { key: entry.publicKey, dsaEncoding: "der" },
      signatureBuf
    );
    if (!valid) {
      throw new Error("Assertion signature verification failed");
    }

    // 6. Extract and verify counter
    if (authDataBuf.length < 37) {
      throw new Error("Authenticator data too short");
    }
    const newCounter = authDataBuf.readUInt32BE(33);
    if (newCounter <= entry.counter) {
      throw new Error(
        `Counter replay: received ${newCounter}, expected > ${entry.counter}`
      );
    }

    // 7. Update counter
    await this.keyStore.updateCounter(keyId, newCounter);

    return keyId;
  }

  /** Extract credentialId from authData (starts at byte 55, length-prefixed). */
  private extractCredentialId(authData: Buffer): Buffer {
    if (authData.length < 55) {
      throw new Error("AuthData too short for credential ID extraction");
    }
    const credIdLen = authData.readUInt16BE(53);
    return authData.subarray(55, 55 + credIdLen);
  }
}
