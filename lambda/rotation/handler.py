"""
Rotation Lambda — automated single-node replacement via share recovery.

Uses EC2 user data (cloud-init) for VM bootstrapping instead of SSM Run
Command, eliminating the SSM agent attack surface. The node's only external
interface is port 3001 (authenticated TOPRF API).

Triggers:
  1. SNS notification from CloudWatch alarm (unhealthy node detected)
  2. EventBridge scheduled event (monthly rotation of all nodes)
  3. Manual invocation (pass node_id or action in event)

Configuration is stored in SSM Parameter Store under /toprf/:
  /toprf/config          — JSON with node configs, threshold, image, etc.
  /toprf/coordinator-config/<node_id> — coordinator config JSON per node

Environment variables:
  SSM_PREFIX             — SSM parameter prefix (default: /toprf)
  DRY_RUN                — if "true", log actions but don't execute
"""

import json
import logging
import os
import re
import shlex
import time
import base64

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SSM_PREFIX = os.environ.get("SSM_PREFIX", "/toprf")
SNS_RESULTS_TOPIC = os.environ.get("SNS_RESULTS_TOPIC", "")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
LOCK_TABLE = os.environ.get("LOCK_TABLE", "toprf-rotation-lock")

# Timeouts (seconds)
BOOT_TIMEOUT = 420         # 7 min for instance boot + Docker setup + image pull
ATTESTATION_TIMEOUT = 180  # 3 min for attestation to appear in S3
RESHARE_TIMEOUT = 120      # 2 min for /reshare response from donor
SEALED_TIMEOUT = 300       # 5 min for new node to combine + seal
HEALTH_TIMEOUT = 120       # 2 min for new node to become healthy
NLB_HEALTH_TIMEOUT = 120   # 2 min for NLB target to become healthy
POLL_INTERVAL = 5          # seconds between polls
LOCK_TTL = 900             # 15 min — matches Lambda max timeout


# ---------------------------------------------------------------------------
# Rotation Lock (prevents concurrent rotations)
# ---------------------------------------------------------------------------

def acquire_lock(node_id):
    """Try to acquire a DynamoDB lock for rotation. Returns True if acquired."""
    if DRY_RUN:
        return True
    dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    table = dynamodb.Table(LOCK_TABLE)
    ttl = int(time.time()) + LOCK_TTL
    try:
        table.put_item(
            Item={"lockId": f"rotation-node-{node_id}", "ttl": ttl},
            ConditionExpression="attribute_not_exists(lockId)",
        )
        logger.info(f"Acquired rotation lock for node {node_id}")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(f"Rotation already in progress for node {node_id} — skipping")
            return False
        raise


def release_lock(node_id):
    """Release the rotation lock."""
    if DRY_RUN:
        return
    try:
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
        table = dynamodb.Table(LOCK_TABLE)
        table.delete_item(Key={"lockId": f"rotation-node-{node_id}"})
        logger.info(f"Released rotation lock for node {node_id}")
    except Exception as e:
        logger.warning(f"Failed to release lock for node {node_id}: {e}")


# ---------------------------------------------------------------------------
# Configuration (SSM Parameter Store — read-only, no agent needed)
# ---------------------------------------------------------------------------

def get_config():
    """Load configuration from SSM Parameter Store."""
    ssm = boto3.client("ssm")
    param = ssm.get_parameter(Name=f"{SSM_PREFIX}/config", WithDecryption=True)
    return json.loads(param["Parameter"]["Value"])


def get_ark_fingerprint():
    """Load AMD ARK fingerprint from SSM (optional)."""
    ssm = boto3.client("ssm")
    try:
        param = ssm.get_parameter(Name=f"{SSM_PREFIX}/ark-fingerprint")
        return param["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        return ""


def get_coordinator_config(node_id):
    """Load coordinator config for a node from SSM."""
    ssm = boto3.client("ssm")
    param = ssm.get_parameter(Name=f"{SSM_PREFIX}/coordinator-config/{node_id}")
    return param["Parameter"]["Value"]


def save_coordinator_config(node_id, config_json):
    """Save updated coordinator config to SSM."""
    ssm = boto3.client("ssm")
    ssm.put_parameter(
        Name=f"{SSM_PREFIX}/coordinator-config/{node_id}",
        Value=config_json,
        Type="String",
        Overwrite=True,
    )


def update_node_config(config, node_id, updates):
    """Update a node's entry in the config and save to SSM."""
    for node in config["nodes"]:
        if node["id"] == node_id:
            node.update(updates)
            break
    ssm = boto3.client("ssm")
    ssm.put_parameter(
        Name=f"{SSM_PREFIX}/config",
        Value=json.dumps(config),
        Type="SecureString",
        Overwrite=True,
    )
    return config


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

def _validate_shell_safe(value, name):
    """Validate that a value is safe for shell interpolation."""
    if not re.match(r'^[a-zA-Z0-9._:/@\-]+$', str(value)):
        raise ValueError(f"Unsafe characters in {name}: {value!r}")
    return str(value)


# ---------------------------------------------------------------------------
# EC2 User Data
# ---------------------------------------------------------------------------

def build_user_data(
    image, bucket, sealed_url, node_id, threshold, total,
    group_public_key, ark_fingerprint, coordinator_config, vs,
):
    """Build a cloud-init user data script for the staging instance.

    The script runs at boot and handles the full lifecycle:
      1. Install Docker
      2. Pull node image
      3. Start init-reshare (blocks until contributions arrive + seal completes)
      4. Write coordinator config
      5. Start normal mode container
    """
    # Shell-quote all string values to prevent injection
    q_image = shlex.quote(image)
    q_bucket = shlex.quote(bucket)
    q_sealed_url = shlex.quote(sealed_url)
    q_group_public_key = shlex.quote(group_public_key)
    q_ark_fingerprint = shlex.quote(ark_fingerprint)
    q_vs = shlex.quote(vs)

    script = f"""#!/bin/bash
set -euo pipefail
exec > /var/log/toprf-init.log 2>&1

echo "[$(date)] Installing Docker..."
yum install -y docker
systemctl enable --now docker

echo "[$(date)] Pulling image: {q_image}"
docker pull {q_image}

echo "[$(date)] Starting init-reshare..."
docker run --name toprf-init-reshare \
    --device /dev/sev-guest:/dev/sev-guest \
    --user root \
    -e AMD_ARK_FINGERPRINT={q_ark_fingerprint} \
    {q_image} \
    --init-reshare \
    --s3-bucket {q_bucket} \
    --upload-url {q_sealed_url} \
    --new-node-id {node_id} \
    --new-threshold {threshold} \
    --new-total-shares {total} \
    --group-public-key {q_group_public_key} \
    --min-contributions {threshold}

EXIT_CODE=$?
echo "[$(date)] init-reshare exited with code $EXIT_CODE"
docker rm -f toprf-init-reshare 2>/dev/null || true

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "[$(date)] FATAL: init-reshare failed"
    exit 1
fi

echo "[$(date)] Writing coordinator config..."
mkdir -p /etc/toprf
cat > /etc/toprf/coordinator.json << 'COORD_EOF'
{coordinator_config}
COORD_EOF

echo "[$(date)] Starting node in normal mode..."
docker run -d --name toprf-node --restart=unless-stopped \
    --device /dev/sev-guest:/dev/sev-guest \
    --user root \
    -p 3001:3001 \
    -e SEALED_KEY_URL={q_sealed_url} \
    -e EXPECTED_VERIFICATION_SHARE={q_vs} \
    -e AMD_ARK_FINGERPRINT={q_ark_fingerprint} \
    -v /etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro \
    {q_image} \
    --port 3001 \
    --coordinator-config /etc/toprf/coordinator.json

echo "[$(date)] Node started. Startup complete."
"""
    return script


def launch_staging_instance(config, node, user_data):
    """Launch a staging EC2 instance with user data (no SSM agent needed)."""
    region = node["region"]
    ec2 = boto3.client("ec2", region_name=region)
    node_id = node["id"]

    instance_type = config.get("instance_type", "c6a.large")
    iam_profile = f"toprf-node-{node_id}-profile"

    ami_id = node.get("ami_id")
    if not ami_id:
        raise ValueError(
            f"ami_id not set for node {node_id}. "
            "Reprovision or set ami_id in SSM config."
        )

    subnet_id = node.get("subnet_id")
    if not subnet_id:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [node["vpc_id"]]}]
        )
        subnet_id = subnets["Subnets"][0]["SubnetId"]

    staging_tag = f"toprf-node-{node_id}-staging"
    logger.info(
        f"Launching staging: region={region}, ami={ami_id}, tag={staging_tag}"
    )

    if DRY_RUN:
        logger.info("DRY_RUN: skipping instance launch")
        return "i-dry-run-placeholder"

    # Encode user data as base64
    user_data_b64 = base64.b64encode(user_data.encode()).decode()

    response = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[node["sg_id"]] if node.get("sg_id") else [],
        IamInstanceProfile={"Name": iam_profile},
        CpuOptions={"AmdSevSnp": "enabled"},
        MetadataOptions={"HttpPutResponseHopLimit": 2},
        UserData=user_data_b64,
        BlockDeviceMappings=[{
            "DeviceName": "/dev/xvda",
            "Ebs": {"VolumeSize": 50, "VolumeType": "gp3"},
        }],
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": staging_tag},
                {"Key": "Project", "Value": "toprf"},
            ],
        }],
    )

    instance_id = response["Instances"][0]["InstanceId"]
    logger.info(f"Staging instance launched: {instance_id}")
    return instance_id


def wait_for_instance(region, instance_id):
    """Wait for an EC2 instance to be running and return its private IP."""
    ec2 = boto3.client("ec2", region_name=region)
    logger.info(f"Waiting for instance {instance_id} to be running...")

    if DRY_RUN:
        return "1.2.3.4"

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"MaxAttempts": 60})

    desc = ec2.describe_instances(InstanceIds=[instance_id])
    private_ip = desc["Reservations"][0]["Instances"][0]["PrivateIpAddress"]
    logger.info(f"Instance {instance_id} running at {private_ip}")
    return private_ip


def terminate_instance(region, instance_id):
    """Terminate an EC2 instance."""
    if DRY_RUN:
        logger.info(f"DRY_RUN: would terminate {instance_id}")
        return

    ec2 = boto3.client("ec2", region_name=region)
    ec2.terminate_instances(InstanceIds=[instance_id])
    logger.info(f"Terminated: {instance_id}")


def retag_instance(region, instance_id, new_name):
    """Update the Name tag on an EC2 instance."""
    if DRY_RUN:
        logger.info(f"DRY_RUN: would retag {instance_id} to {new_name}")
        return

    ec2 = boto3.client("ec2", region_name=region)
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[{"Key": "Name", "Value": new_name}],
    )
    logger.info(f"Retagged {instance_id} to {new_name}")


# ---------------------------------------------------------------------------
# S3 Operations
# ---------------------------------------------------------------------------

def wait_for_s3_object(bucket, key, region, timeout):
    """Poll S3 until an object appears or timeout."""
    s3 = _s3_client_for_bucket()
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            s3.head_object(Bucket=bucket, Key=key)
            logger.info(f"Found s3://{bucket}/{key}")
            return True
        except ClientError:
            time.sleep(POLL_INTERVAL)

    return False


def _s3_client_for_bucket():
    """Return an S3 client routed through the VPC Gateway endpoint.

    The Lambda runs in a VPC with an S3 Gateway endpoint in eu-west-1.
    S3 buckets are globally addressable, so we always use the eu-west-1
    regional endpoint regardless of the bucket's region. This avoids
    ConnectTimeoutErrors when accessing cross-region buckets (e.g.
    us-east-2) that would otherwise bypass the Gateway endpoint."""
    return boto3.client("s3", region_name="eu-west-1")


def download_s3_object(bucket, key, region):
    """Download an S3 object and return its bytes."""
    s3 = _s3_client_for_bucket()
    response = s3.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()


def upload_s3_object(bucket, key, data, region):
    """Upload bytes to S3."""
    s3 = _s3_client_for_bucket()
    s3.put_object(Bucket=bucket, Key=key, Body=data)
    logger.info(f"Uploaded s3://{bucket}/{key}")


def cleanup_reshare_artifacts(bucket, region):
    """Remove temporary reshare artifacts from S3."""
    s3 = _s3_client_for_bucket()
    response = s3.list_objects_v2(Bucket=bucket, Prefix="reshare/")
    for obj in response.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
        logger.info(f"Cleaned up s3://{bucket}/{obj['Key']}")


# ---------------------------------------------------------------------------
# NLB Operations
# ---------------------------------------------------------------------------

def wait_target_healthy(region, tg_arn, ip, label, timeout=NLB_HEALTH_TIMEOUT):
    """Wait for a target to become healthy in a target group. Returns True if healthy."""
    if DRY_RUN:
        return True

    elbv2 = boto3.client("elbv2", region_name=region)
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = elbv2.describe_target_health(
            TargetGroupArn=tg_arn,
            Targets=[{"Id": ip, "Port": 3001}],
        )
        state = resp["TargetHealthDescriptions"][0]["TargetHealth"]["State"]
        if state == "healthy":
            logger.info(f"{ip} healthy in {label}")
            return True
        time.sleep(POLL_INTERVAL)

    logger.warning(f"{ip} not healthy in {label} after {timeout}s — continuing")
    return False


def swap_nlb_target(region, tg_arn, old_ip, new_ip, label="NLB"):
    """Register new target, wait for healthy, then deregister old target."""
    if DRY_RUN:
        logger.info(f"DRY_RUN: would swap {old_ip} -> {new_ip} in {tg_arn}")
        return

    elbv2 = boto3.client("elbv2", region_name=region)

    # Register new target first
    elbv2.register_targets(
        TargetGroupArn=tg_arn,
        Targets=[{"Id": new_ip, "Port": 3001}],
    )
    logger.info(f"Registered {new_ip} in {label}")

    # Wait for healthy before removing old
    healthy = wait_target_healthy(region, tg_arn, new_ip, label)
    if not healthy:
        logger.error(f"New target {new_ip} not healthy — aborting swap for {label}")
        raise RuntimeError(f"New target {new_ip} not healthy in {label}")

    # Deregister old target
    if old_ip:
        elbv2.deregister_targets(
            TargetGroupArn=tg_arn,
            Targets=[{"Id": old_ip, "Port": 3001}],
        )
        logger.info(f"Deregistered {old_ip} from {label}")


# ---------------------------------------------------------------------------
# Health Checks
# ---------------------------------------------------------------------------

def check_donor_health(donor_node):
    """Health-check a donor node via its NLB endpoint."""
    import urllib.request

    endpoint = donor_node["nlb_endpoint"]
    url = f"{endpoint}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            if body.get("status") == "ready":
                return True
    except Exception as e:
        logger.warning(f"Health check failed for node {donor_node['id']}: {e}")
    return False


def check_staging_health(staging_ip, timeout=HEALTH_TIMEOUT):
    """Health-check a staging node via direct HTTP to its private IP."""
    import urllib.request

    url = f"http://{staging_ip}:3001/health"
    deadline = time.time() + timeout
    logger.info(f"Waiting for staging node at {url}...")

    if DRY_RUN:
        return True

    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode())
                if body.get("status") == "ready":
                    logger.info(f"Staging node healthy at {staging_ip}")
                    return True
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)

    logger.warning(f"Staging node not healthy after {timeout}s")
    return False


# ---------------------------------------------------------------------------
# Reshare Orchestration
# ---------------------------------------------------------------------------

def send_reshare_request(donor_node, reshare_payload):
    """Send POST /reshare to a donor node via its NLB endpoint."""
    import urllib.request
    import urllib.error

    endpoint = donor_node["nlb_endpoint"]
    url = f"{endpoint}/reshare"

    data = json.dumps(reshare_payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    logger.info(f"Sending /reshare to node {donor_node['id']} at {endpoint}")

    try:
        with urllib.request.urlopen(req, timeout=RESHARE_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
            logger.info(f"Received contribution from node {donor_node['id']}")
            return body
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        logger.error(
            f"Failed to get contribution from node {donor_node['id']}: "
            f"HTTP {e.code} — {error_body}"
        )
        raise
    except Exception as e:
        logger.error(
            f"Failed to get contribution from node {donor_node['id']}: {e}"
        )
        raise


def orchestrate_reshare(config, node_id, bucket, region):
    """
    Orchestrate the reshare: download attestation from staging node's S3,
    send /reshare to each donor, upload contributions to staging node's S3.
    """
    # Validate node_id to prevent S3 key path traversal
    node_id_str = str(node_id)
    if not re.match(r'^\d+$', node_id_str):
        raise ValueError(f"Invalid node ID: {node_id_str!r}")

    group_public_key = config["group_public_key"]
    donor_nodes = [n for n in config["nodes"] if n["id"] != node_id]
    donor_ids = [n["id"] for n in donor_nodes]

    # Wait for attestation artifacts from staging node
    logger.info("Waiting for attestation artifacts in S3...")
    for key in [
        "reshare/attestation.bin",
        "reshare/pubkey.bin",
        "reshare/certs.bin",
    ]:
        if not wait_for_s3_object(bucket, key, region, ATTESTATION_TIMEOUT):
            raise TimeoutError(
                f"Timed out waiting for {key} in s3://{bucket}"
            )

    # Download artifacts
    attestation = download_s3_object(
        bucket, "reshare/attestation.bin", region
    )
    pubkey = download_s3_object(bucket, "reshare/pubkey.bin", region)
    certs = download_s3_object(bucket, "reshare/certs.bin", region)

    # expected_measurement is not sent — each donor checks against its own
    # compiled-in measurement, so a compromised orchestrator cannot
    # substitute a rogue measurement.
    reshare_payload = {
        "target_pubkey": pubkey.hex(),
        "attestation_report": base64.b64encode(attestation).decode(),
        "cert_chain": base64.b64encode(certs).decode(),
        "new_node_id": node_id,
        "participant_ids": donor_ids,
        "group_public_key": group_public_key,
    }

    if DRY_RUN:
        logger.info("DRY_RUN: would send /reshare to donors")
        return

    # Send /reshare to each donor and upload contributions
    for donor in donor_nodes:
        contribution = send_reshare_request(donor, reshare_payload)

        # Upload contribution to staging node's S3 for it to pick up
        donor_id = str(donor['id'])
        if not re.match(r'^\d+$', donor_id):
            raise ValueError(f"Invalid donor node ID: {donor_id!r}")
        contrib_key = f"reshare/contribution-from-{donor_id}.json"
        upload_s3_object(
            bucket,
            contrib_key,
            json.dumps(contribution).encode(),
            region,
        )


# ---------------------------------------------------------------------------
# Single-Node Rotation (Staging-Based, SSM-Free)
# ---------------------------------------------------------------------------

def rotate_node(config, node_id):
    """
    Replace a single node using staging-based approach + share recovery.

    Old node continues serving traffic throughout. If anything fails,
    the staging instance is terminated and the old node is unaffected.

    All VM bootstrapping is done via EC2 user data (cloud-init) — no SSM
    Run Command, no SSH. The node's only interface is port 3001 (TOPRF API).

    Steps:
      0. Acquire rotation lock (prevents concurrent rotations)
      1. Pre-flight: verify donor nodes are healthy
      2. Clean up stale reshare/staging artifacts
      3. Launch staging instance with user data
      4. Wait for attestation artifacts in S3
      5. Orchestrate reshare: /reshare to donors, upload contributions
      6. Wait for sealed blob in S3 (init-reshare done)
      7. Health-check staging node via direct HTTP
      8. Swap NLB targets (per-node + frontend)
      9. Terminate old, retag staging, update config
    """
    if not acquire_lock(node_id):
        return {"status": "skipped", "reason": "rotation already in progress"}
    node = next(n for n in config["nodes"] if n["id"] == node_id)
    bucket = node["s3_bucket"]
    region = node["region"]
    old_ip = node.get("private_ip")
    old_instance = node.get("instance_id")
    tg_arn = node.get("tg_arn")

    image = _validate_shell_safe(
        config.get("node_image", "ghcr.io/jeganggs64/toprf-node:latest"),
        "node_image",
    )
    ark_fingerprint = _validate_shell_safe(get_ark_fingerprint(), "ark_fingerprint")
    threshold = int(config["threshold"])
    total = len(config["nodes"])
    group_public_key = _validate_shell_safe(
        config["group_public_key"], "gpk"
    )

    sealed_key = f"node-{node_id}-sealed.bin"
    sealed_url = f"s3://{bucket}/{sealed_key}"

    vs = node.get("verification_share", "")
    if vs:
        _validate_shell_safe(vs, "verification_share")

    logger.info(f"=== Rotating node {node_id} (region={region}) ===")

    # ── Step 1: Pre-flight donor health checks ──
    logger.info("Step 1: Pre-flight donor health checks")
    donor_nodes = [n for n in config["nodes"] if n["id"] != node_id]
    for donor in donor_nodes:
        if not check_donor_health(donor):
            raise RuntimeError(
                f"Donor node {donor['id']} is not healthy — aborting rotation"
            )
        logger.info(f"  Node {donor['id']}: healthy")

    # ── Step 2: Clean up stale artifacts ──
    logger.info("Step 2: Cleaning stale artifacts")
    cleanup_reshare_artifacts(bucket, region)

    # ── Step 3: Launch staging instance with user data ──
    logger.info("Step 3: Launching staging instance")

    coord_config = get_coordinator_config(node_id)
    user_data = build_user_data(
        image=image,
        bucket=bucket,
        sealed_url=sealed_url,
        node_id=node_id,
        threshold=threshold,
        total=total,
        group_public_key=group_public_key,
        ark_fingerprint=ark_fingerprint,
        coordinator_config=coord_config,
        vs=vs,
    )

    staging_id = launch_staging_instance(config, node, user_data)
    staging_ip = wait_for_instance(region, staging_id)

    try:
        # ── Step 4: Wait for attestation artifacts ──
        logger.info("Step 4: Waiting for attestation artifacts in S3")

        # User data installs Docker + pulls image first (~2-4 min),
        # then starts init-reshare which uploads attestation to S3.
        # Use a longer timeout to account for boot + Docker setup.
        for key in [
            "reshare/attestation.bin",
            "reshare/pubkey.bin",
            "reshare/certs.bin",
        ]:
            if not wait_for_s3_object(bucket, key, region, BOOT_TIMEOUT):
                raise TimeoutError(
                    f"Timed out waiting for {key} in s3://{bucket} "
                    f"(includes boot + Docker setup time)"
                )

        # ── Step 5: Orchestrate reshare ──
        logger.info("Step 5: Orchestrating reshare")
        orchestrate_reshare(config, node_id, bucket, region)

        # ── Step 6: Wait for sealed blob ──
        logger.info("Step 6: Waiting for sealed blob in S3")
        if not wait_for_s3_object(bucket, sealed_key, region, SEALED_TIMEOUT):
            raise TimeoutError(
                "Sealed blob not found — init-reshare may have failed. "
                "Check /var/log/toprf-init.log on the instance."
            )
        logger.info("  Sealed blob uploaded")

        # ── Step 7: Health check via HTTP ──
        logger.info("Step 7: Health-checking staging node via HTTP")

        # After init-reshare completes, the user data script starts the
        # normal mode container. Give it a moment to boot.
        if not check_staging_health(staging_ip):
            raise TimeoutError(
                "Staging node not healthy after starting normal mode"
            )

        # ── Step 8: Swap NLB targets ──
        logger.info("Step 8: Swapping NLB targets")

        # Per-node NLB
        if tg_arn:
            swap_nlb_target(
                region, tg_arn, old_ip, staging_ip,
                f"per-node NLB (node {node_id})",
            )
        else:
            logger.warning(
                "No per-node TG ARN — skipping per-node NLB swap"
            )

        # Frontend NLB (only if node is in the coordinator VPC)
        frontend_tg = config.get("frontend_tg_arn")
        coordinator_vpc = config.get("coordinator_vpc_id")
        node_vpc = node.get("vpc_id")
        if frontend_tg and coordinator_vpc and node_vpc == coordinator_vpc:
            swap_nlb_target(
                region, frontend_tg, old_ip, staging_ip,
                f"frontend NLB (node {node_id})",
            )

        # ── Step 9: Finalize ──
        logger.info("Step 9: Finalizing")

        # Terminate old instance
        if old_instance:
            terminate_instance(region, old_instance)

        # Retag staging -> permanent
        retag_instance(region, staging_id, f"toprf-node-{node_id}")

        # Update SSM config with new instance info
        update_node_config(config, node_id, {
            "instance_id": staging_id,
            "private_ip": staging_ip,
        })

        # Clean up reshare artifacts
        cleanup_reshare_artifacts(bucket, region)

        logger.info(f"=== Node {node_id} rotation complete ===")
        release_lock(node_id)
        return {
            "node_id": node_id,
            "region": region,
            "old_instance_id": old_instance,
            "new_instance_id": staging_id,
        }

    except Exception:
        logger.error(
            f"Rotation failed for node {node_id}, "
            f"terminating staging instance {staging_id}"
        )
        terminate_instance(region, staging_id)
        cleanup_reshare_artifacts(bucket, region)
        release_lock(node_id)
        raise


# ---------------------------------------------------------------------------
# Success Notifications
# ---------------------------------------------------------------------------

def notify_success(trigger, summary, details=None):
    """Publish a rotation-success message to the results SNS topic."""
    if not SNS_RESULTS_TOPIC:
        logger.info("SNS_RESULTS_TOPIC not set — skipping notification")
        return
    sns = boto3.client("sns")
    body = {
        "trigger": trigger,
        "summary": summary,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if details:
        body["details"] = details
    sns.publish(
        TopicArn=SNS_RESULTS_TOPIC,
        Subject=f"[TOPRF] {summary}",
        Message=json.dumps(body, indent=2),
    )
    logger.info(f"Success notification sent: {summary}")


# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

def parse_sns_alarm(event):
    """Extract the unhealthy node ID from an SNS CloudWatch alarm."""
    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        alarm_name = message.get("AlarmName", "")

        # Alarm name format: toprf-node-<id>-unhealthy
        if (
            alarm_name.startswith("toprf-node-")
            and alarm_name.endswith("-unhealthy")
        ):
            try:
                node_id = int(alarm_name.split("-")[2])
                state = message.get("NewStateValue", "")
                if state == "ALARM":
                    return node_id
            except (IndexError, ValueError):
                pass

    return None


def handler(event, context):
    """
    Lambda entry point.

    Handles:
      - SNS event from CloudWatch alarm -> rotate the unhealthy node
      - EventBridge scheduled event -> rotate all nodes one at a time
      - Manual invocation -> {"node_id": N}
    """
    # Log event type without full payload to avoid leaking config details
    event_source = event.get(
        "source",
        event.get("Records", [{}])[0].get("EventSource", "manual"),
    )
    logger.info(f"Event received: source={event_source}")

    config = get_config()

    # SNS trigger (unhealthy node)
    if "Records" in event and event["Records"][0].get(
        "EventSource"
    ) == "aws:sns":
        node_id = parse_sns_alarm(event)
        if node_id is None:
            logger.info("SNS event is not an ALARM trigger — ignoring")
            return {"statusCode": 200, "body": "not an alarm"}

        logger.info(f"CloudWatch alarm: node {node_id} is unhealthy")
        result = rotate_node(config, node_id)
        notify_success(
            "alarm",
            f"Node {node_id} reprovisioned (unhealthy)",
            details=result,
        )
        return {"statusCode": 200, "body": f"rotated node {node_id}"}

    # EventBridge scheduled trigger (monthly rotation — oldest node only)
    if (
        event.get("source") == "aws.events"
        or event.get("detail-type") == "Scheduled Event"
    ):
        # Find the oldest node by EC2 LaunchTime
        oldest_node_id = None
        oldest_launch = None
        for node in config["nodes"]:
            instance_id = node.get("instance_id")
            if not instance_id:
                continue
            try:
                ec2 = boto3.client("ec2", region_name=node["region"])
                resp = ec2.describe_instances(InstanceIds=[instance_id])
                launch_time = resp["Reservations"][0]["Instances"][0]["LaunchTime"]
                logger.info(
                    f"  Node {node['id']} ({instance_id}): launched {launch_time}"
                )
                if oldest_launch is None or launch_time < oldest_launch:
                    oldest_launch = launch_time
                    oldest_node_id = node["id"]
            except Exception as e:
                logger.warning(
                    f"  Could not get launch time for node {node['id']}: {e}"
                )

        if oldest_node_id is None:
            logger.error("No nodes with valid instance IDs — aborting")
            return {"statusCode": 500, "body": "no valid nodes to rotate"}

        logger.info(
            f"Scheduled rotation: rotating oldest node {oldest_node_id} "
            f"(launched {oldest_launch})"
        )
        try:
            result = rotate_node(config, oldest_node_id)
        except Exception as e:
            logger.error(f"Failed to rotate node {oldest_node_id}: {e}")
            return {
                "statusCode": 500,
                "body": f"rotation failed at node {oldest_node_id}: {e}",
            }
        notify_success(
            "scheduled",
            f"Monthly rotation: node {oldest_node_id} replaced (oldest)",
            details=result,
        )
        return {
            "statusCode": 200,
            "body": f"rotated oldest node {oldest_node_id}",
        }

    # Manual invocation (single node)
    node_id = event.get("node_id")
    if node_id:
        result = rotate_node(config, int(node_id))
        notify_success(
            "manual",
            f"Node {node_id} rotated (manual)",
            details=result,
        )
        return {"statusCode": 200, "body": f"rotated node {node_id}"}

    logger.warning(f"Unknown event type: {json.dumps(event)}")
    return {"statusCode": 400, "body": "unknown event type"}
