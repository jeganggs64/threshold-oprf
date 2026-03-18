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
 * Android tokens contain { deviceUUID } (registered via /attest with Play Integrity).
 * iOS tokens contain { keyId, assertion }.
 */
function detectPlatform(tokenB64: string): "ios" | "android" {
  try {
    const parsed = JSON.parse(Buffer.from(tokenB64, "base64").toString("utf8"));
    if (parsed.deviceUUID && !parsed.keyId) return "android";
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

  let deviceId: string;
  if (platform === "android") {
    // Android uses a two-phase model (mirroring iOS):
    //   1. /attest registers the device via Play Integrity (non-VPC, can reach Google)
    //   2. /evaluate checks the stored device record (VPC, no external calls)
    const parsed = JSON.parse(Buffer.from(attestationToken, "base64").toString("utf8"));
    const uuid = parsed.deviceUUID;
    if (!uuid) throw new Error("Missing deviceUUID in attestation token");

    deviceId = `android:${uuid}`;

    // Verify device was registered via /attest
    const entry = await getKeyStore().getKey(deviceId);
    if (!entry) {
      throw new Error("Device not registered. Call /attest first.");
    }
  } else {
    deviceId = await getProvider().verify(attestationToken, nonce);
  }

  // Per-device rate limiting
  await checkDeviceRateLimit(deviceId);

  return deviceId;
}
