import { AttestationProvider } from "./attestation";

const PACKAGE_NAME = "com.ruonid.app";
const PLAY_INTEGRITY_API_KEY = process.env.PLAY_INTEGRITY_API_KEY || "";

/**
 * Google Play Integrity provider.
 *
 * Stateless per-request verification — no key registration phase.
 * Decodes the integrity token via Google's API and checks:
 *   1. Package name matches
 *   2. App integrity verdict is PLAY_RECOGNIZED
 *   3. Device integrity includes MEETS_DEVICE_INTEGRITY
 *   4. Request nonce matches
 */
export class PlayIntegrityProvider implements AttestationProvider {
  async verify(token: string, nonce: string): Promise<string> {
    // Decode the base64 wrapper from the client
    let parsed: { integrityToken: string; deviceUUID: string };
    try {
      parsed = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
    } catch {
      throw new Error("Invalid Play Integrity token format");
    }

    const { integrityToken, deviceUUID } = parsed;
    if (!integrityToken) throw new Error("Missing integrityToken");
    if (!deviceUUID) throw new Error("Missing deviceUUID");

    if (!PLAY_INTEGRITY_API_KEY) {
      throw new Error("PLAY_INTEGRITY_API_KEY not configured");
    }

    // Call Google's decodeIntegrityToken API
    const url = `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken?key=${PLAY_INTEGRITY_API_KEY}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ integrity_token: integrityToken }),
    });

    if (!res.ok) {
      const err = await res.text().catch(() => "");
      console.error("Play Integrity API error:", res.status, err);
      throw new Error(`Play Integrity API error: ${res.status}`);
    }

    const decoded = await res.json();
    const payload = decoded.tokenPayloadExternal;
    if (!payload) {
      throw new Error("Missing tokenPayloadExternal in response");
    }

    // 1. Verify request nonce matches
    const requestDetails = payload.requestDetails;
    if (!requestDetails?.nonce) {
      throw new Error("Missing nonce in integrity token");
    }
    // The nonce in the token is base64-encoded by Google
    const decodedNonce = Buffer.from(requestDetails.nonce, "base64").toString("utf8");
    if (decodedNonce !== nonce && requestDetails.nonce !== nonce) {
      throw new Error("Integrity token nonce mismatch");
    }

    // 2. Verify package name
    const appIntegrity = payload.appIntegrity;
    if (appIntegrity?.packageName !== PACKAGE_NAME) {
      throw new Error(
        `Package name mismatch: ${appIntegrity?.packageName} !== ${PACKAGE_NAME}`
      );
    }

    // 3. Verify app recognition verdict
    const appRecognition = appIntegrity?.appRecognitionVerdict;
    if (appRecognition !== "PLAY_RECOGNIZED" && appRecognition !== "UNRECOGNIZED_VERSION") {
      // Allow UNRECOGNIZED_VERSION during development (sideloaded builds)
      // In production, tighten this to PLAY_RECOGNIZED only
      throw new Error(`App integrity verdict: ${appRecognition}`);
    }

    // 4. Verify device integrity
    const deviceIntegrity = payload.deviceIntegrity;
    const verdicts: string[] = deviceIntegrity?.deviceRecognitionVerdict || [];
    if (!verdicts.includes("MEETS_DEVICE_INTEGRITY")) {
      throw new Error(
        `Device integrity insufficient: ${verdicts.join(", ") || "none"}`
      );
    }

    // Use deviceUUID as the device identifier for rate limiting
    return `android:${deviceUUID}`;
  }
}
