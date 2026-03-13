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

# Validate required config
for _var in ACCOUNT_ID REGION LAMBDA_PREFIX; do
  [[ -n "${!_var:-}" ]] || { echo "ERROR: $_var not set in config.env"; exit 1; }
done

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
node build.mjs || { echo "ERROR: Build failed"; exit 1; }
[[ -d dist ]] || { echo "ERROR: dist/ directory not found after build"; exit 1; }
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

    # Wait for code update to complete before applying config changes
    echo "  Waiting for code update to finish..."
    local _wait_attempts=0
    while true; do
      local _update_status
      _update_status=$(aws lambda get-function --function-name "$func_name" --region "$REGION" \
        --query 'Configuration.LastUpdateStatus' --output text 2>/dev/null) || true
      if [[ "$_update_status" == "Successful" ]]; then
        break
      elif [[ "$_update_status" == "Failed" ]]; then
        echo "  ERROR: Code update failed for $func_name"
        return 1
      fi
      _wait_attempts=$((_wait_attempts + 1))
      if [[ $_wait_attempts -ge 30 ]]; then
        echo "  WARNING: Timed out waiting for code update (status: $_update_status)"
        break
      fi
      sleep 2
    done

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

    # Wait for config update to complete (especially important for VPC changes)
    echo "  Waiting for config update to finish..."
    _wait_attempts=0
    while true; do
      local _config_status
      _config_status=$(aws lambda get-function --function-name "$func_name" --region "$REGION" \
        --query 'Configuration.LastUpdateStatus' --output text 2>/dev/null) || true
      if [[ "$_config_status" == "Successful" ]]; then
        break
      elif [[ "$_config_status" == "Failed" ]]; then
        echo "  ERROR: Config update failed for $func_name"
        return 1
      fi
      _wait_attempts=$((_wait_attempts + 1))
      if [[ $_wait_attempts -ge 60 ]]; then
        echo "  WARNING: Timed out waiting for config update (status: $_config_status)"
        break
      fi
      sleep 2
    done
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

    # Wait for function to become active (VPC functions need ENI provisioning)
    echo "  Waiting for function to become active..."
    local _create_attempts=0
    while true; do
      local _func_state
      _func_state=$(aws lambda get-function --function-name "$func_name" --region "$REGION" \
        --query 'Configuration.State' --output text 2>/dev/null) || true
      if [[ "$_func_state" == "Active" ]]; then
        break
      elif [[ "$_func_state" == "Failed" ]]; then
        echo "  ERROR: Function creation failed for $func_name"
        return 1
      fi
      _create_attempts=$((_create_attempts + 1))
      if [[ $_create_attempts -ge 60 ]]; then
        echo "  WARNING: Timed out waiting for function to become active (state: $_func_state)"
        break
      fi
      sleep 2
    done
  fi

  # Grant API Gateway invoke permission (idempotent)
  aws lambda add-permission \
    --function-name "$func_name" \
    --statement-id apigateway-invoke \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*" \
    --region "$REGION" 2>/dev/null || true

  # Clean up zip artifact
  rm -f "$zip_path"

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
