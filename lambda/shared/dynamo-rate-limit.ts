import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const TABLE = process.env.DEVICE_KEYS_TABLE || "ruonid-device-keys";
const REGION = process.env.DEVICE_KEYS_REGION || "eu-west-1";

/** Max requests per device per window. */
const MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX || "7", 10);

/** Window duration in ms (default 1 hour). */
const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || "3600000", 10);

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: REGION })
);

/**
 * Per-device rate limiter backed by the device-keys DynamoDB table.
 *
 * Uses an atomic conditional update on the existing device key record:
 * - If the current window has expired, resets the counter and starts a new window.
 * - If within the window, increments the counter and rejects if over the limit.
 *
 * This avoids a separate table — the device-keys table already has one row per device.
 */
export async function checkDeviceRateLimit(deviceId: string): Promise<void> {
  const now = Date.now();
  const windowStart = now - WINDOW_MS;

  try {
    // Attempt to increment counter within the current window.
    // Condition: window is still active AND count is below limit.
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE,
        Key: { keyId: deviceId },
        UpdateExpression: "SET rateLimitCount = rateLimitCount + :one",
        ConditionExpression:
          "attribute_exists(rateLimitWindowStart) AND rateLimitWindowStart > :windowStart AND rateLimitCount < :maxReq",
        ExpressionAttributeValues: {
          ":one": 1,
          ":windowStart": windowStart,
          ":maxReq": MAX_REQUESTS,
        },
      })
    );
  } catch (err: any) {
    if (err.name !== "ConditionalCheckFailedException") throw err;

    // Condition failed — either window expired, fields don't exist, or limit reached.
    // Try to reset the window. This only succeeds if the window has expired or fields are missing.
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE,
          Key: { keyId: deviceId },
          UpdateExpression:
            "SET rateLimitCount = :one, rateLimitWindowStart = :now",
          ConditionExpression:
            "attribute_not_exists(rateLimitWindowStart) OR rateLimitWindowStart <= :windowStart",
          ExpressionAttributeValues: {
            ":one": 1,
            ":now": now,
            ":windowStart": windowStart,
          },
        })
      );
    } catch (resetErr: any) {
      if (resetErr.name === "ConditionalCheckFailedException") {
        // Window is still active but count >= limit — rate limited.
        throw new RateLimitError();
      }
      throw resetErr;
    }
  }
}

export class RateLimitError extends Error {
  constructor() {
    super("Rate limit exceeded");
    this.name = "RateLimitError";
  }
}
