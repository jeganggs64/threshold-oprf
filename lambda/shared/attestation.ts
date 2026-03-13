import { AppleAppAttestProvider } from "../lib/providers/attestation";
import { DynamoDeviceKeyStore } from "./dynamo-device-keys";
import { consumeNonce } from "./dynamo-nonces";
import { checkDeviceRateLimit } from "./dynamo-rate-limit";

const APPLE_APP_ID = process.env.APPLE_APP_ID || "";
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID || "";

let provider: AppleAppAttestProvider | null = null;
let keyStore: DynamoDeviceKeyStore | null = null;

function getKeyStore(): DynamoDeviceKeyStore {
  if (!keyStore) keyStore = new DynamoDeviceKeyStore();
  return keyStore;
}

function getProvider(): AppleAppAttestProvider {
  if (!provider) {
    provider = new AppleAppAttestProvider(
      APPLE_APP_ID,
      APPLE_TEAM_ID,
      getKeyStore(),
    );
  }
  return provider;
}

export { getProvider, getKeyStore };

/**
 * Verify attestation from request body.
 * Returns deviceId on success, throws on failure.
 */
export async function verifyAttestation(body: {
  attestationToken?: string;
  nonce?: string;
}): Promise<string> {
  const { attestationToken, nonce } = body;

  if (!attestationToken) throw new Error("Missing attestationToken");
  if (!nonce) throw new Error("Missing nonce");

  // Consume nonce (single-use + TTL)
  const valid = await consumeNonce(nonce);
  if (!valid) throw new Error("Invalid or expired nonce");

  // Verify assertion
  const deviceId = await getProvider().verify(attestationToken, nonce);

  // Per-device rate limiting
  await checkDeviceRateLimit(deviceId);

  return deviceId;
}
