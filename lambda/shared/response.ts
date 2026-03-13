/** Lambda HTTP response helpers for API Gateway v2. */

export interface LambdaResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

const CORS_HEADERS: Record<string, string> = {
  "Content-Type": "application/json",
};

export function json(statusCode: number, body: unknown): LambdaResponse {
  return {
    statusCode,
    headers: CORS_HEADERS,
    body: JSON.stringify(body),
  };
}

export function ok(body: unknown): LambdaResponse {
  return json(200, body);
}

export function error(statusCode: number, message: string): LambdaResponse {
  return json(statusCode, { error: message });
}
