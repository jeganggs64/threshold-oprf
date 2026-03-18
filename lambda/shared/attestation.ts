import { AppleAppAttestProvider } from "../lib/providers/attestation";
import { PlayIntegrityProvider } from "../lib/providers/play-integrity";
import { DynamoDeviceKeyStore } from "./dynamo-device-keys";
import { consumeNonce } from "./dynamo-nonces";
import { checkDeviceRateLimit } from "./dynamo-rate-limit";

const APPLE_APP_ID = process.env.APPLE_APP_ID || "";
const APPLE_TEAM_ID = process.env.APPLE_TEAM_ID || "";

let appleProvider: AppleAppAttestProvider | null = null;
let playProvider: PlayIntegrityProvider | null = null;
let keyStore: DynamoDeviceKeyStore | null = null;

function getKeyStore(): DynamoDeviceKeyStore {
  if (!keyStore) keyStore = new DynamoDeviceKeyStore();
  return keyStore;
}

function getProvider(): AppleAppAttestProvider {
  if (!appleProvider) {
    appleProvider = new AppleAppAttestProvider(
      APPLE_APP_ID,
      APPLE_TEAM_ID,
      getKeyStore(),
    );
  }
  return appleProvider;
}

function getPlayProvider(): PlayIntegrityProvider {
  if (!playProvider) {
    playProvider = new PlayIntegrityProvider();
  }
  return playProvider;
}

export { getProvider, getKeyStore, getPlayProvider };

/**
 * Detect platform from the attestation token.
 * Android tokens contain { integrityToken, deviceUUID }.
 * iOS tokens contain { keyId, assertion }.
 */
function detectPlatform(tokenB64: string): "ios" | "android" {
  try {
    const parsed = JSON.parse(Buffer.from(tokenB64, "base64").toString("utf8"));
    if (parsed.integrityToken) return "android";
  } catch {}
  return "ios";
}

/**
 * Verify attestation from request body.
 * Returns deviceId on success, throws on failure.
 * Supports both Apple App Attest (iOS) and Google Play Integrity (Android).
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

  // Verify assertion — route to the correct provider based on token format
  const platform = detectPlatform(attestationToken);
  const deviceId = platform === "android"
    ? await getPlayProvider().verify(attestationToken, nonce)
    : await getProvider().verify(attestationToken, nonce);

  // Per-device rate limiting
  await checkDeviceRateLimit(deviceId);

  return deviceId;
}
