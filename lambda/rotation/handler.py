"""
Rotation Lambda — automated single-node replacement via share recovery.

Triggers:
  1. SNS notification from CloudWatch alarm (unhealthy node detected)
  2. EventBridge scheduled event (monthly rotation of all nodes)

The Lambda replaces one node at a time using the share recovery protocol.
The existing quorum produces a new share for the replacement node without
reconstructing the secret.

Configuration is stored in SSM Parameter Store under /toprf/:
  /toprf/config          — JSON with node configs, threshold, image, etc.
  /toprf/measurement     — expected binary measurement (hex)
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

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SSM_PREFIX = os.environ.get("SSM_PREFIX", "/toprf")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

# Timeouts
VM_BOOT_TIMEOUT = 300       # 5 min for VM to boot and start init-reshare
ATTESTATION_TIMEOUT = 180   # 3 min for attestation to appear in S3
RESHARE_TIMEOUT = 120       # 2 min for /reshare response from donor
SEALED_TIMEOUT = 300        # 5 min for new node to combine + seal
HEALTH_TIMEOUT = 120        # 2 min for new node to become healthy
POLL_INTERVAL = 5           # seconds between S3 polls


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def get_config():
    """Load configuration from SSM Parameter Store."""
    ssm = boto3.client("ssm")
    param = ssm.get_parameter(Name=f"{SSM_PREFIX}/config", WithDecryption=True)
    return json.loads(param["Parameter"]["Value"])


def get_measurement():
    """Load expected measurement from SSM."""
    ssm = boto3.client("ssm")
    param = ssm.get_parameter(Name=f"{SSM_PREFIX}/measurement")
    return param["Parameter"]["Value"]


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
# EC2 Operations
# ---------------------------------------------------------------------------

def _validate_shell_safe(value, name):
    """Validate that a value is safe for shell interpolation (alphanumeric, hyphens, dots, colons, slashes)."""
    if not re.match(r'^[a-zA-Z0-9._:/@\-]+$', str(value)):
        raise ValueError(f"Unsafe characters in {name}: {value!r}")
    return str(value)


def build_user_data(config, node, image):
    """Build EC2 user data script that bootstraps init-reshare."""
    node_id = int(node["id"])
    bucket = _validate_shell_safe(node["s3_bucket"], "s3_bucket")
    threshold = int(config["threshold"])
    total = len(config["nodes"])
    group_public_key = _validate_shell_safe(config["group_public_key"], "group_public_key")
    image = _validate_shell_safe(image, "image")

    # Donor IDs = all nodes except the one being replaced
    donor_ids = [n["id"] for n in config["nodes"] if n["id"] != node_id]
    min_contributions = threshold

    measurement = _validate_shell_safe(get_measurement(), "measurement")

    script = f"""#!/bin/bash
set -euo pipefail
exec > /var/log/toprf-rotation.log 2>&1

echo "=== TOPRF Rotation Bootstrap ==="
echo "Node ID: {node_id}"
echo "S3 Bucket: {bucket}"

# Install Docker
yum install -y docker
systemctl start docker
systemctl enable docker

# Pull node image
docker pull {shlex.quote(image)}

# Run init-reshare mode
echo "Starting init-reshare..."
docker run --rm --name toprf-init-reshare \\
    --device /dev/sev-guest:/dev/sev-guest \\
    --cap-drop ALL --security-opt no-new-privileges:true \\
    {shlex.quote(image)} \\
    --init-reshare \\
    --s3-bucket {shlex.quote(bucket)} \\
    --upload-url {shlex.quote('s3://' + bucket + '/sealed.bin')} \\
    --new-node-id {node_id} \\
    --new-threshold {threshold} \\
    --new-total-shares {total} \\
    --group-public-key {shlex.quote(group_public_key)} \\
    --min-contributions {min_contributions}

echo "Init-reshare complete. Starting normal mode..."

# Write coordinator config (uploaded by Lambda via S3)
mkdir -p /etc/toprf
aws s3 cp {shlex.quote('s3://' + bucket + '/coordinator.json')} /etc/toprf/coordinator.json

# Start in normal mode
docker run -d --name toprf-node --restart=unless-stopped \\
    -e SEALED_KEY_URL={shlex.quote('s3://' + bucket + '/sealed.bin')} \\
    -e EXPECTED_PEER_MEASUREMENT={shlex.quote(measurement)} \\
    --device /dev/sev-guest:/dev/sev-guest \\
    --cap-drop ALL --security-opt no-new-privileges:true \\
    -p 3001:3001 \\
    {shlex.quote(image)} \\
    --port 3001 \\
    --coordinator-config /etc/toprf/coordinator.json

echo "=== TOPRF node started ==="
"""
    return base64.b64encode(script.encode()).decode()


def launch_instance(config, node):
    """Launch a new SEV-SNP EC2 instance for a node."""
    region = node["region"]
    ec2 = boto3.client("ec2", region_name=region)

    instance_type = config.get("instance_type", "c6a.large")
    iam_profile = f"toprf-node-{node['id']}-profile"
    image = config.get("node_image", "ghcr.io/jeganggs64/toprf-node:latest")

    # Use pinned AMI from node config (set at provision time).
    # This ensures rotated nodes use the same AMI as the original deployment,
    # keeping the SEV-SNP measurement stable. To update the AMI, redeploy
    # all nodes from scratch.
    ami_id = node.get("ami_id")
    if not ami_id:
        raise ValueError(
            f"ami_id not set for node {node['id']}. "
            "Reprovision nodes or set ami_id in SSM config."
        )

    # Find a subnet in the target VPC
    subnet_id = node.get("subnet_id")
    if not subnet_id:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [node["vpc_id"]]}]
        )
        subnet_id = subnets["Subnets"][0]["SubnetId"]

    user_data = build_user_data(config, node, image)

    logger.info(f"Launching instance: region={region}, ami={ami_id}, type={instance_type}")

    if DRY_RUN:
        logger.info("DRY_RUN: skipping instance launch")
        return "i-dry-run-placeholder"

    response = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[node["sg_id"]] if node.get("sg_id") else [],
        IamInstanceProfile={"Name": iam_profile},
        UserData=user_data,
        CpuOptions={"AmdSevSnp": "enabled"},
        MetadataOptions={"HttpPutResponseHopLimit": 2},
        BlockDeviceMappings=[{
            "DeviceName": "/dev/xvda",
            "Ebs": {"VolumeSize": 50, "VolumeType": "gp3"},
        }],
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": f"toprf-node-{node['id']}"},
                {"Key": "Project", "Value": "toprf"},
            ],
        }],
    )

    instance_id = response["Instances"][0]["InstanceId"]
    logger.info(f"Instance launched: {instance_id}")
    return instance_id


def wait_for_instance(region, instance_id):
    """Wait for an EC2 instance to be running."""
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
    logger.info(f"Terminated instance {instance_id}")


# ---------------------------------------------------------------------------
# S3 Operations
# ---------------------------------------------------------------------------

def wait_for_s3_object(bucket, key, region, timeout):
    """Poll S3 until an object appears or timeout."""
    s3 = boto3.client("s3", region_name=region)
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            s3.head_object(Bucket=bucket, Key=key)
            logger.info(f"Found s3://{bucket}/{key}")
            return True
        except s3.exceptions.ClientError:
            time.sleep(POLL_INTERVAL)

    return False


def download_s3_object(bucket, key, region):
    """Download an S3 object and return its bytes."""
    s3 = boto3.client("s3", region_name=region)
    response = s3.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()


def upload_s3_object(bucket, key, data, region):
    """Upload bytes to S3."""
    s3 = boto3.client("s3", region_name=region)
    s3.put_object(Bucket=bucket, Key=key, Body=data)
    logger.info(f"Uploaded s3://{bucket}/{key}")


def upload_coordinator_config(config, node):
    """Generate and upload coordinator config for a node to its S3 bucket."""
    node_id = node["id"]
    bucket = node["s3_bucket"]
    region = node["region"]

    peers = []
    for other in config["nodes"]:
        if other["id"] == node_id:
            continue
        peers.append({
            "node_id": other["id"],
            "endpoint": other["nlb_endpoint"],
            "verification_share": other["verification_share"],
        })

    coord_config = json.dumps({"peers": peers}, indent=2)
    upload_s3_object(bucket, "coordinator.json", coord_config.encode(), region)

    # Also save to SSM for future reference
    save_coordinator_config(node_id, coord_config)


def cleanup_reshare_artifacts(bucket, region):
    """Remove temporary reshare artifacts from S3."""
    s3 = boto3.client("s3", region_name=region)
    prefixes = ["reshare/"]
    for prefix in prefixes:
        response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in response.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
            logger.info(f"Cleaned up s3://{bucket}/{obj['Key']}")


# ---------------------------------------------------------------------------
# NLB Operations
# ---------------------------------------------------------------------------

def swap_nlb_target(region, tg_arn, old_ip, new_ip):
    """Deregister old target and register new target in an NLB target group."""
    if DRY_RUN:
        logger.info(f"DRY_RUN: would swap {old_ip} → {new_ip} in {tg_arn}")
        return

    elbv2 = boto3.client("elbv2", region_name=region)

    # Register new target
    elbv2.register_targets(
        TargetGroupArn=tg_arn,
        Targets=[{"Id": new_ip, "Port": 3001}],
    )
    logger.info(f"Registered new target {new_ip}:3001")

    # Wait for new target to be healthy before deregistering old
    deadline = time.time() + HEALTH_TIMEOUT
    while time.time() < deadline:
        health = elbv2.describe_target_health(
            TargetGroupArn=tg_arn,
            Targets=[{"Id": new_ip, "Port": 3001}],
        )
        state = health["TargetHealthDescriptions"][0]["TargetHealth"]["State"]
        if state == "healthy":
            logger.info(f"New target {new_ip} is healthy")
            break
        time.sleep(POLL_INTERVAL)
    else:
        raise TimeoutError(f"New target {new_ip} did not become healthy within {HEALTH_TIMEOUT}s")

    # Deregister old target
    if old_ip:
        elbv2.deregister_targets(
            TargetGroupArn=tg_arn,
            Targets=[{"Id": old_ip, "Port": 3001}],
        )
        logger.info(f"Deregistered old target {old_ip}:3001")


# ---------------------------------------------------------------------------
# Reshare Orchestration
# ---------------------------------------------------------------------------

def send_reshare_request(donor_node, reshare_payload):
    """Send POST /reshare to a donor node via its NLB endpoint."""
    import urllib.request

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
    except Exception as e:
        logger.error(f"Failed to get contribution from node {donor_node['id']}: {e}")
        raise


def orchestrate_reshare(config, node_id, new_node_bucket, new_node_region):
    """
    Orchestrate the reshare: download attestation from new node's S3,
    send /reshare to each donor, upload contributions to new node's S3.
    """
    group_public_key = config["group_public_key"]
    donor_nodes = [n for n in config["nodes"] if n["id"] != node_id]
    donor_ids = [n["id"] for n in donor_nodes]

    # Wait for attestation artifacts from new node
    logger.info("Waiting for attestation artifacts in S3...")
    for key in ["reshare/attestation.bin", "reshare/pubkey.bin", "reshare/certs.bin"]:
        if not wait_for_s3_object(new_node_bucket, key, new_node_region, ATTESTATION_TIMEOUT):
            raise TimeoutError(f"Timed out waiting for {key} in s3://{new_node_bucket}")

    # Download artifacts
    attestation = download_s3_object(new_node_bucket, "reshare/attestation.bin", new_node_region)
    pubkey = download_s3_object(new_node_bucket, "reshare/pubkey.bin", new_node_region)
    certs = download_s3_object(new_node_bucket, "reshare/certs.bin", new_node_region)

    # expected_measurement is not sent — each donor reads it from its own
    # EXPECTED_PEER_MEASUREMENT env var, so a compromised orchestrator
    # cannot substitute a rogue measurement.
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

        # Upload contribution to new node's S3 for it to pick up
        contrib_key = f"reshare/contribution-from-{donor['id']}.json"
        upload_s3_object(
            new_node_bucket,
            contrib_key,
            json.dumps(contribution).encode(),
            new_node_region,
        )


# ---------------------------------------------------------------------------
# Single-Node Rotation
# ---------------------------------------------------------------------------

def rotate_node(config, node_id):
    """
    Replace a single node using the share recovery protocol.

    Steps:
      1. Upload coordinator config to new node's S3
      2. Launch new VM (user data starts init-reshare, then normal mode)
      3. Wait for attestation, send /reshare to donors, upload contributions
      4. Wait for sealed blob (init-reshare finished combining)
      5. Wait for new node to become healthy
      6. Swap NLB target (register new, deregister old)
      7. Terminate old VM
      8. Update config with new instance info
    """
    node = next(n for n in config["nodes"] if n["id"] == node_id)
    bucket = node["s3_bucket"]
    region = node["region"]
    old_ip = node.get("private_ip")
    old_instance = node.get("instance_id")
    tg_arn = node.get("tg_arn")

    logger.info(f"=== Rotating node {node_id} (region={region}) ===")

    # Step 1: Upload coordinator config for the new node
    logger.info("Step 1: Uploading coordinator config to S3")
    upload_coordinator_config(config, node)

    # Step 1b: Delete stale sealed.bin to prevent TOCTOU race
    # (old sealed.bin from previous node would cause us to proceed
    # before the new node has actually finished sealing)
    logger.info("Step 1b: Deleting stale sealed.bin")
    s3 = boto3.client("s3", region_name=region)
    try:
        s3.delete_object(Bucket=bucket, Key="sealed.bin")
    except Exception:
        pass  # may not exist

    # Step 2: Launch new instance
    logger.info("Step 2: Launching new instance")
    new_instance_id = launch_instance(config, node)
    new_ip = wait_for_instance(region, new_instance_id)

    try:
        # Step 3: Orchestrate reshare
        logger.info("Step 3: Orchestrating reshare")
        orchestrate_reshare(config, node_id, bucket, region)

        # Step 4: Wait for sealed blob (init-reshare completed)
        logger.info("Step 4: Waiting for sealed blob")
        if not wait_for_s3_object(bucket, "sealed.bin", region, SEALED_TIMEOUT):
            raise TimeoutError("Timed out waiting for sealed blob")
        logger.info("Sealed blob found — init-reshare complete")

        # Step 5: Wait for node to become healthy via NLB
        logger.info("Step 5: Waiting for new node to become healthy")
        if tg_arn:
            # Step 6: Swap NLB target
            logger.info("Step 6: Swapping NLB target")
            swap_nlb_target(region, tg_arn, old_ip, new_ip)
        else:
            logger.warning("No TG ARN configured — skipping NLB swap")

        # Step 7: Terminate old instance
        if old_instance:
            logger.info(f"Step 7: Terminating old instance {old_instance}")
            terminate_instance(region, old_instance)
        else:
            logger.info("Step 7: No old instance to terminate")

        # Step 8: Update config
        logger.info("Step 8: Updating config")
        update_node_config(config, node_id, {
            "instance_id": new_instance_id,
            "private_ip": new_ip,
            "ip": "",  # public IP unknown until queried
        })

        # Clean up reshare artifacts
        cleanup_reshare_artifacts(bucket, region)

        logger.info(f"=== Node {node_id} rotation complete ===")

    except Exception:
        # Rollback: terminate new instance if anything fails after launch
        logger.error(f"Rotation failed for node {node_id}, terminating new instance {new_instance_id}")
        terminate_instance(region, new_instance_id)
        cleanup_reshare_artifacts(bucket, region)
        raise


# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

def parse_sns_alarm(event):
    """Extract the unhealthy node ID from an SNS CloudWatch alarm notification."""
    for record in event.get("Records", []):
        message = json.loads(record["Sns"]["Message"])
        alarm_name = message.get("AlarmName", "")

        # Alarm name format: toprf-node-<id>-unhealthy
        if alarm_name.startswith("toprf-node-") and alarm_name.endswith("-unhealthy"):
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
      - SNS event from CloudWatch alarm → rotate the unhealthy node
      - EventBridge scheduled event → rotate all nodes one at a time
    """
    logger.info(f"Event: {json.dumps(event)}")

    config = get_config()

    # SNS trigger (unhealthy node)
    if "Records" in event and event["Records"][0].get("EventSource") == "aws:sns":
        node_id = parse_sns_alarm(event)
        if node_id is None:
            logger.info("SNS event is not an ALARM trigger — ignoring")
            return {"statusCode": 200, "body": "not an alarm"}

        logger.info(f"CloudWatch alarm: node {node_id} is unhealthy")
        rotate_node(config, node_id)
        return {"statusCode": 200, "body": f"rotated node {node_id}"}

    # EventBridge scheduled trigger (monthly rotation)
    if event.get("source") == "aws.events" or event.get("detail-type") == "Scheduled Event":
        threshold = config["threshold"]
        logger.info("Scheduled rotation: rotating all nodes")
        for node in config["nodes"]:
            # Re-read config each iteration (rotate_node updates it)
            config = get_config()
            # Quorum check: ensure enough healthy nodes remain before rotating
            healthy = sum(1 for n in config["nodes"] if n.get("instance_id"))
            if healthy < threshold:
                logger.error(
                    f"Only {healthy} healthy nodes, need {threshold} — aborting rotation"
                )
                return {
                    "statusCode": 500,
                    "body": f"quorum lost: {healthy} < {threshold}",
                }
            try:
                rotate_node(config, node["id"])
            except Exception as e:
                logger.error(f"Failed to rotate node {node['id']}: {e}")
                # Stop — don't risk further reducing the quorum
                return {
                    "statusCode": 500,
                    "body": f"rotation failed at node {node['id']}: {e}",
                }
        return {"statusCode": 200, "body": "scheduled rotation complete"}

    # Manual invocation (pass node_id in event)
    node_id = event.get("node_id")
    if node_id:
        rotate_node(config, int(node_id))
        return {"statusCode": 200, "body": f"rotated node {node_id}"}

    logger.warning(f"Unknown event type: {json.dumps(event)}")
    return {"statusCode": 400, "body": "unknown event type"}
