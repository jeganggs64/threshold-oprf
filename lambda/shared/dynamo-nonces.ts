import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  DeleteCommand,
  GetCommand,
} from "@aws-sdk/lib-dynamodb";
import { randomBytes } from "crypto";

const TABLE = process.env.NONCES_TABLE || "ruonid-nonces";
const TTL_MS = parseInt(process.env.NONCE_TTL_MS || "60000", 10);
const REGION = process.env.NONCES_REGION || "eu-west-1";

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: REGION })
);

/** Issue a new nonce and store it in DynamoDB with TTL. */
export async function issueNonce(): Promise<string> {
  const nonce = randomBytes(32).toString("hex");
  const now = Date.now();
  await ddb.send(
    new PutCommand({
      TableName: TABLE,
      Item: {
        nonce,
        createdAt: now,
        ttl: Math.floor((now + TTL_MS) / 1000), // DynamoDB TTL in seconds
      },
    })
  );
  return nonce;
}

/**
 * Consume a nonce (single-use). Returns true if valid.
 * Deletes the nonce atomically with a condition to prevent double-use.
 */
export async function consumeNonce(nonce: string): Promise<boolean> {
  try {
    const result = await ddb.send(
      new DeleteCommand({
        TableName: TABLE,
        Key: { nonce },
        ConditionExpression: "attribute_exists(nonce)",
        ReturnValues: "ALL_OLD",
      })
    );
    if (!result.Attributes) return false;
    // Check if expired
    const createdAt = result.Attributes.createdAt as number;
    if (Date.now() - createdAt > TTL_MS) return false;
    return true;
  } catch (err: any) {
    if (err.name === "ConditionalCheckFailedException") return false;
    throw err;
  }
}
