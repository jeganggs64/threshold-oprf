import { issueNonce } from "../shared/dynamo-nonces";
import { ok, error } from "../shared/response";

/** GET /challenge — issue a single-use nonce for attestation. */
export async function handler() {
  try {
    const nonce = await issueNonce();
    return ok({ nonce });
  } catch (err: any) {
    console.error("challenge error:", err);
    return error(500, "Failed to issue challenge");
  }
}
