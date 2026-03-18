import { getProvider, getPlayProvider } from "../shared/attestation";
import { consumeNonce } from "../shared/dynamo-nonces";
import { ok, error } from "../shared/response";

/**
 * POST /attest — device registration.
 *
 * iOS:     One-time Apple App Attest key registration (attestationObject + keyId + nonce).
 * Android: No-op registration. Android uses stateless Play Integrity tokens per-request,
 *          so this endpoint just validates the token and returns a deviceId.
 */
export async function handler(event: any) {
  try {
    const body = JSON.parse(event.body || "{}");
    const { nonce } = body;

    if (!nonce || typeof nonce !== "string") {
      return error(400, "Missing or invalid nonce");
    }

    // Detect platform from request body
    if (body.integrityToken) {
      // ── Android: verify Play Integrity token ──
      const deviceId = await getPlayProvider().verify(
        Buffer.from(JSON.stringify({
          integrityToken: body.integrityToken,
          deviceUUID: body.deviceUUID || "",
        })).toString("base64"),
        nonce,
      );

      const valid = await consumeNonce(nonce);
      if (!valid) {
        return error(403, "Invalid or expired nonce");
      }

      return ok({ deviceId });
    }

    // ── iOS: Apple App Attest one-time key registration ──
    const { attestationObject, keyId } = body;

    if (!attestationObject || typeof attestationObject !== "string") {
      return error(400, "Missing or invalid attestationObject");
    }
    if (!keyId || typeof keyId !== "string") {
      return error(400, "Missing or invalid keyId");
    }

    // Verify attestation BEFORE consuming nonce — if attestation fails,
    // the nonce remains valid for a legitimate retry.
    const deviceId = await getProvider().attest(attestationObject, keyId, nonce);

    // Consume nonce only after successful attestation (single-use + TTL)
    const valid = await consumeNonce(nonce);
    if (!valid) {
      return error(403, "Invalid or expired nonce");
    }

    return ok({ deviceId });
  } catch (err: any) {
    console.error("attest error:", err.message);
    return error(403, "Attestation failed");
  }
}
