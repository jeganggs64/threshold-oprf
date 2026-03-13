import { getProvider } from "../shared/attestation";
import { consumeNonce } from "../shared/dynamo-nonces";
import { ok, error } from "../shared/response";

/** POST /attest — one-time Apple App Attest device key registration. */
export async function handler(event: any) {
  try {
    const body = JSON.parse(event.body || "{}");
    const { attestationObject, keyId, nonce } = body;

    if (!attestationObject || typeof attestationObject !== "string") {
      return error(400, "Missing or invalid attestationObject");
    }
    if (!keyId || typeof keyId !== "string") {
      return error(400, "Missing or invalid keyId");
    }
    if (!nonce || typeof nonce !== "string") {
      return error(400, "Missing or invalid nonce");
    }

    // Consume nonce (single-use + TTL)
    const valid = await consumeNonce(nonce);
    if (!valid) {
      return error(403, "Invalid or expired nonce");
    }

    const deviceId = await getProvider().attest(attestationObject, keyId, nonce);
    return ok({ deviceId });
  } catch (err: any) {
    console.error("attest error:", err.message);
    return error(403, "Attestation failed");
  }
}
