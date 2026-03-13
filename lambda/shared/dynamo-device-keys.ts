import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { DeviceKeyStore, DeviceKeyEntry } from "../lib/stores/deviceKeys";

const TABLE = process.env.DEVICE_KEYS_TABLE || "ruonid-device-keys";
const REGION = process.env.DEVICE_KEYS_REGION || "eu-west-1";

const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: REGION })
);

/** DynamoDB-backed device key store for Lambda. */
export class DynamoDeviceKeyStore implements DeviceKeyStore {
  async saveKey(
    keyId: string,
    publicKey: string,
    counter: number
  ): Promise<void> {
    await ddb.send(
      new PutCommand({
        TableName: TABLE,
        Item: {
          keyId,
          publicKey,
          counter,
          createdAt: Date.now(),
        },
      })
    );
  }

  async getKey(keyId: string): Promise<DeviceKeyEntry | null> {
    const result = await ddb.send(
      new GetCommand({
        TableName: TABLE,
        Key: { keyId },
      })
    );
    if (!result.Item) return null;
    return result.Item as DeviceKeyEntry;
  }

  async updateCounter(keyId: string, counter: number): Promise<void> {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE,
        Key: { keyId },
        UpdateExpression: "SET #c = :counter",
        ExpressionAttributeNames: { "#c": "counter" },
        ExpressionAttributeValues: { ":counter": counter },
        ConditionExpression: "attribute_exists(keyId)",
      })
    );
  }
}
