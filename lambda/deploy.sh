#!/usr/bin/env bash
# Deploy OPRF Lambda functions (challenge, attest, evaluate).
# Usage: ./lambda/deploy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Load config from gitignored file
CONFIG_FILE="$SCRIPT_DIR/config.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "ERROR: Missing $CONFIG_FILE"
  echo "Copy config.env.example to config.env and fill in values."
  exit 1
fi
# shellcheck source=/dev/null
source "$CONFIG_FILE"

ROLE_ARN="${ROLE_ARN:-arn:aws:iam::${ACCOUNT_ID}:role/toprf-lambda-exec}"
DIST_DIR="$(cd "$SCRIPT_DIR/dist" 2>/dev/null && pwd || echo "$SCRIPT_DIR/dist")"

# Environment variables for OPRF Lambdas
ENV_VARS="{
  \"Variables\": {
    \"APPLE_APP_ID\": \"${APPLE_APP_ID}\",
    \"APPLE_TEAM_ID\": \"${APPLE_TEAM_ID}\",
    \"NONCES_REGION\": \"${REGION}\",
    \"DEVICE_KEYS_REGION\": \"${REGION}\",
    \"NONCES_TABLE\": \"${NONCES_TABLE}\",
    \"DEVICE_KEYS_TABLE\": \"${DEVICE_KEYS_TABLE}\",
    \"NLB_URL\": \"${NLB_URL}\"
  }
}"

echo "=== Building OPRF Lambda handlers ==="
cd "$PROJECT_ROOT"
node build.mjs
DIST_DIR="$(cd dist && pwd)"

deploy_lambda() {
  local name="$1"
  local handler_file="$2"
  local timeout="${3:-30}"
  local memory="${4:-256}"
  local vpc_config="${5:-}"
  local func_name="${LAMBDA_PREFIX}-${name}"

  echo ""
  echo "--- Deploying $func_name ---"

  # Create zip
  local zip_path="/tmp/${func_name}.zip"
  cd "$DIST_DIR"
  cp "${handler_file}.mjs" index.mjs
  zip -j "$zip_path" index.mjs > /dev/null
  rm index.mjs
  cd - > /dev/null

  # Check if function exists
  if aws lambda get-function --function-name "$func_name" --region "$REGION" > /dev/null 2>&1; then
    echo "  Updating code..."
    aws lambda update-function-code \
      --function-name "$func_name" \
      --zip-file "fileb://$zip_path" \
      --region "$REGION" \
      --query 'FunctionName' --output text > /dev/null

    aws lambda wait function-updated --function-name "$func_name" --region "$REGION" 2>/dev/null || sleep 5

    echo "  Updating config..."
    local config_args=(
      --function-name "$func_name"
      --timeout "$timeout"
      --memory-size "$memory"
      --environment "$ENV_VARS"
      --role "$ROLE_ARN"
      --region "$REGION"
    )
    if [[ -n "$vpc_config" ]]; then
      config_args+=(--vpc-config "$vpc_config")
    fi
    aws lambda update-function-configuration "${config_args[@]}" \
      --query 'FunctionName' --output text > /dev/null
  else
    echo "  Creating function..."
    local create_args=(
      --function-name "$func_name"
      --runtime nodejs20.x
      --handler index.handler
      --role "$ROLE_ARN"
      --zip-file "fileb://$zip_path"
      --timeout "$timeout"
      --memory-size "$memory"
      --environment "$ENV_VARS"
      --region "$REGION"
    )
    if [[ -n "$vpc_config" ]]; then
      create_args+=(--vpc-config "$vpc_config")
    fi
    aws lambda create-function "${create_args[@]}" \
      --query 'FunctionName' --output text > /dev/null
  fi

  # Grant API Gateway invoke permission (idempotent)
  aws lambda add-permission \
    --function-name "$func_name" \
    --statement-id apigateway-invoke \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*" \
    --region "$REGION" 2>/dev/null || true

  echo "  Done: $func_name"
}

# Deploy OPRF Lambda functions
deploy_lambda "challenge"  "challenge"  10  128
deploy_lambda "attest"     "attest"     30  256
deploy_lambda "evaluate"   "evaluate"   60  256 "SubnetIds=${VPC_SUBNETS},SecurityGroupIds=${VPC_SG}"

echo ""
echo "=== OPRF Lambda deployment complete ==="
echo ""
echo "Endpoints (via API Gateway ${API_ID}):"
echo "  GET  /challenge"
echo "  POST /attest"
echo "  POST /evaluate"
echo ""
