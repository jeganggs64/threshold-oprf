import { verifyAttestation } from "../shared/attestation";
import { RateLimitError } from "../shared/dynamo-rate-limit";
import { ok, error } from "../shared/response";

const NLB_URL =
  process.env.NLB_URL ||
  "http://toprf-node-1-nlb-b640dedf5418a6b4.elb.eu-west-1.amazonaws.com:3001";

/**
 * POST /evaluate — attestation-gated threshold OPRF evaluation.
 *
 * Verifies device attestation, then proxies the blinded point
 * to the coordinator node via the internal NLB.
 */
export async function handler(event: any) {
  try {
    const body = JSON.parse(event.body || "{}");
    const { blindedPoint } = body;

    if (!blindedPoint || typeof blindedPoint !== "string") {
      return error(400, "Missing or invalid blindedPoint");
    }

    // Validate blindedPoint is a compressed secp256k1 point
    if (!/^(02|03)[0-9a-f]{64}$/.test(blindedPoint)) {
      return error(
        400,
        "blindedPoint must be a valid compressed secp256k1 point (66 hex chars starting with 02 or 03)"
      );
    }

    // Verify device attestation + per-device rate limit
    try {
      await verifyAttestation(body);
    } catch (err: any) {
      if (err instanceof RateLimitError) {
        return error(429, "Too many requests from this device");
      }
      console.error("attestation failed:", err.message);
      return error(403, err.message || "Attestation verification failed");
    }

    // Proxy to coordinator node via NLB
    const nodeRes = await fetch(`${NLB_URL}/evaluate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blinded_point: blindedPoint }),
      signal: AbortSignal.timeout(30_000),
    });

    if (!nodeRes.ok) {
      const err = await nodeRes.json().catch(() => ({}));
      console.error("node error:", nodeRes.status, err);
      if (nodeRes.status === 503) {
        return error(503, "Service temporarily unavailable");
      }
      return error(502, "OPRF evaluation failed");
    }

    const result = await nodeRes.json();
    return ok(result);
  } catch (err: any) {
    console.error("evaluate error:", err.message);
    return error(502, "OPRF evaluation failed");
  }
}
