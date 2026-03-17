"""
Rotation Lambda — automated single-node replacement via share recovery.

Uses SSM Run Command for VM operations (Docker install, image pull, container
management) instead of EC2 user data, giving step-by-step observability and
error handling. Follows a staging-based approach: a new instance runs alongside
the old node until verified healthy, then the swap happens atomically.

Triggers:
  1. SNS notification from CloudWatch alarm (unhealthy node detected)
  2. EventBridge scheduled event (monthly rotation of all nodes)
  3. Manual invocation (pass node_id or action in event)

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
import time
import base64

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SSM_PREFIX = os.environ.get("SSM_PREFIX", "/toprf")
SNS_RESULTS_TOPIC = os.environ.get("SNS_RESULTS_TOPIC", "")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

# Timeouts (seconds)
SSM_AGENT_TIMEOUT = 300     # 5 min for SSM agent to come online
DOCKER_SETUP_TIMEOUT = 300  # 5 min for Docker install + image pull
ATTESTATION_TIMEOUT = 180   # 3 min for attestation to appear in S3
RESHARE_TIMEOUT = 120       # 2 min for /reshare response from donor
SEALED_TIMEOUT = 300        # 5 min for new node to combine + seal
HEALTH_TIMEOUT = 120        # 2 min for new node to become healthy
NLB_HEALTH_TIMEOUT = 120    # 2 min for NLB target to become healthy
POLL_INTERVAL = 5           # seconds between polls


# ---------------------------------------------------------------------------
# Configuration (SSM Parameter Store)
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
# SSM Run Command
# ---------------------------------------------------------------------------

def wait_for_ssm_agent(region, instance_id):
    """Wait for the SSM agent on an instance to become online."""
    ssm = boto3.client("ssm", region_name=region)
    deadline = time.time() + SSM_AGENT_TIMEOUT
    logger.info(f"Waiting for SSM agent on {instance_id}...")

    while time.time() < deadline:
        try:
            resp = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            if resp["InstanceInformationList"]:
                if resp["InstanceInformationList"][0].get("PingStatus") == "Online":
                    logger.info(f"SSM agent online: {instance_id}")
                    return
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)

    raise TimeoutError(
        f"SSM agent not online on {instance_id} within {SSM_AGENT_TIMEOUT}s"
    )


def run_ssm_command(region, instance_id, commands, comment="", timeout=300):
    """Execute shell commands on an instance via SSM Run Command.

    Returns stdout on success, raises on failure or timeout.
    """
    ssm = boto3.client("ssm", region_name=region)
    if isinstance(commands, str):
        commands = [commands]

    if DRY_RUN:
        logger.info(f"DRY_RUN: would run on {instance_id}: {commands[0][:80]}")
        return ""

    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        Comment=(comment or "toprf-rotation")[:100],
        TimeoutSeconds=timeout,
    )
    command_id = resp["Command"]["CommandId"]
    logger.info(f"SSM command {command_id}: {comment or commands[0][:50]}")

    deadline = time.time() + timeout + 30  # extra buffer for API
    while time.time() < deadline:
        try:
            result = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            status = result["Status"]
            if status == "Success":
                return result.get("StandardOutputContent", "")
            elif status in ("Failed", "TimedOut", "Cancelled"):
                stderr = result.get("StandardErrorContent", "")
                raise RuntimeError(
                    f"SSM command failed ({status}): {stderr[:500]}"
                )
        except ssm.exceptions.InvocationDoesNotExist:
            pass  # Not ready yet
        time.sleep(POLL_INTERVAL)

    raise TimeoutError(f"SSM command {command_id} timed out")


# ---------------------------------------------------------------------------
# EC2 Operations
# ---------------------------------------------------------------------------

def launch_staging_instance(config, node):
    """Launch a staging EC2 instance for rotation (no user data — SSM used)."""
    region = node["region"]
    ec2 = boto3.client("ec2", region_name=region)
    node_id = node["id"]

    instance_type = config.get("instance_type", "c6a.large")
    iam_profile = f"toprf-node-{node_id}-profile"

    # Use pinned AMI from node config (set at provision time).
    # Keeps the SEV-SNP measurement stable across rotations.
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
    """Wait for a target to become healthy in a target group."""
    if DRY_RUN:
        return

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
            return
        time.sleep(POLL_INTERVAL)

    logger.warning(f"{ip} not healthy in {label} after {timeout}s — continuing")


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
    wait_target_healthy(region, tg_arn, new_ip, label)

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


def check_staging_health_via_ssm(region, instance_id, timeout=HEALTH_TIMEOUT):
    """Health-check a staging node via SSM (runs curl loop on instance).

    Efficient: one SSM call with internal polling instead of repeated SSM calls.
    """
    attempts = timeout // 2
    try:
        result = run_ssm_command(region, instance_id, [
            f"for i in $(seq 1 {attempts}); do "
            f"  if curl -sf http://localhost:3001/health 2>/dev/null "
            f"    | grep -q ready; then "
            f"    echo HEALTHY; exit 0; "
            f"  fi; "
            f"  sleep 2; "
            f"done; "
            f"echo NOT_HEALTHY; exit 1",
        ], comment="Health check loop", timeout=timeout + 30)
        return "HEALTHY" in result
    except RuntimeError:
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

        # Upload contribution to staging node's S3 for it to pick up
        contrib_key = f"reshare/contribution-from-{donor['id']}.json"
        upload_s3_object(
            bucket,
            contrib_key,
            json.dumps(contribution).encode(),
            region,
        )


# ---------------------------------------------------------------------------
# Docker Command Builders
# ---------------------------------------------------------------------------

def _build_docker_run_cmd(
    name, image, args, env=None, volumes=None, detach=True, port=None,
):
    """Build a docker run command string with security options."""
    parts = ["docker run"]
    if detach:
        parts.append("-d")
    parts.extend(["--name", name, "--restart=unless-stopped"])
    parts.extend([
        "--device /dev/sev-guest:/dev/sev-guest",
        "--user root",
    ])
    if port:
        parts.append(f"-p {port}:{port}")
    for k, v in (env or {}).items():
        parts.append(f"-e {k}='{v}'")
    for v in (volumes or []):
        parts.append(f"-v {v}")
    parts.append(image)
    parts.extend(args)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Single-Node Rotation (Staging-Based)
# ---------------------------------------------------------------------------

def rotate_node(config, node_id):
    """
    Replace a single node using staging-based approach + share recovery.

    Old node continues serving traffic throughout. If anything fails,
    the staging instance is terminated and the old node is unaffected.

    Steps:
      1. Pre-flight: verify donor nodes are healthy
      2. Clean up stale reshare/staging artifacts
      3. Launch staging instance (no user data — SSM used)
      4. Setup staging VM: install Docker, pull image (via SSM)
      5. Start init-reshare on staging (via SSM)
      6. Orchestrate reshare: attestation -> /reshare to donors -> contributions
      7. Wait for staging node to seal
      8. Start normal mode on staging, health-check (via SSM)
      9. Swap NLB targets (per-node + frontend)
      10. Terminate old, retag staging, rename S3 blob, update config
    """
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
    measurement = _validate_shell_safe(get_measurement(), "measurement")
    ark_fingerprint = _validate_shell_safe(get_ark_fingerprint(), "ark_fingerprint")
    threshold = int(config["threshold"])
    total = len(config["nodes"])
    group_public_key = _validate_shell_safe(
        config["group_public_key"], "gpk"
    )

    staging_sealed_key = f"node-{node_id}-staging-sealed.bin"
    staging_sealed_url = f"s3://{bucket}/{staging_sealed_key}"
    canonical_sealed_key = f"node-{node_id}-sealed.bin"
    canonical_sealed_url = f"s3://{bucket}/{canonical_sealed_key}"

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
    s3 = _s3_client_for_bucket()
    try:
        s3.delete_object(Bucket=bucket, Key=staging_sealed_key)
    except Exception:
        pass

    # ── Step 3: Launch staging instance ──
    logger.info("Step 3: Launching staging instance")
    staging_id = launch_staging_instance(config, node)
    staging_ip = wait_for_instance(region, staging_id)

    try:
        # ── Step 4: Setup staging VM via SSM ──
        logger.info("Step 4: Setting up staging VM via SSM")
        wait_for_ssm_agent(region, staging_id)

        run_ssm_command(
            region, staging_id,
            ["yum install -y docker && systemctl enable --now docker"],
            comment=f"Install Docker on node-{node_id}-staging",
            timeout=DOCKER_SETUP_TIMEOUT,
        )
        logger.info("  Docker installed")

        run_ssm_command(
            region, staging_id,
            [f"docker pull {image}"],
            comment=f"Pull image on node-{node_id}-staging",
            timeout=DOCKER_SETUP_TIMEOUT,
        )
        logger.info(f"  Image pulled: {image}")

        # ── Step 5: Start init-reshare ──
        logger.info("Step 5: Starting init-reshare on staging")
        _validate_shell_safe(bucket, "bucket")

        init_cmd = _build_docker_run_cmd(
            "toprf-init-reshare", image,
            args=[
                "--init-reshare",
                f"--s3-bucket {bucket}",
                f"--upload-url {staging_sealed_url}",
                f"--new-node-id {node_id}",
                f"--new-threshold {threshold}",
                f"--new-total-shares {total}",
                f"--group-public-key {group_public_key}",
                f"--min-contributions {threshold}",
            ],
            env={"AMD_ARK_FINGERPRINT": ark_fingerprint},
        )
        run_ssm_command(
            region, staging_id, [init_cmd],
            comment=f"Init-reshare on node-{node_id}-staging",
        )

        # ── Step 6: Orchestrate reshare ──
        logger.info("Step 6: Orchestrating reshare")
        orchestrate_reshare(config, node_id, bucket, region)

        # ── Step 7: Wait for seal ──
        logger.info("Step 7: Waiting for init-reshare to complete")
        try:
            exit_code = run_ssm_command(
                region, staging_id,
                ["docker wait toprf-init-reshare"],
                comment=f"Wait init-reshare node-{node_id}",
                timeout=SEALED_TIMEOUT,
            )
            exit_code = exit_code.strip()
            if exit_code != "0":
                logs = run_ssm_command(
                    region, staging_id,
                    ["docker logs --tail 30 toprf-init-reshare 2>&1"],
                    comment="Get init-reshare logs",
                )
                raise RuntimeError(
                    f"Init-reshare exited {exit_code}: {logs[:500]}"
                )
        except TimeoutError:
            raise TimeoutError("Init-reshare timed out waiting for seal")

        if not wait_for_s3_object(bucket, staging_sealed_key, region, 30):
            raise TimeoutError(
                "Sealed blob not found after init-reshare completed"
            )
        logger.info("  Sealed blob uploaded")

        run_ssm_command(
            region, staging_id,
            ["docker rm -f toprf-init-reshare 2>/dev/null || true"],
            comment="Cleanup init-reshare container",
        )

        # ── Step 8: Start normal mode ──
        logger.info("Step 8: Starting staging node in normal mode")

        # Reuse the existing coordinator config (same VPC, same PrivateLink
        # endpoints — only the instance behind the NLB changed)
        coord_config = get_coordinator_config(node_id)

        # Write coordinator config + start node via SSM
        node_cmd = _build_docker_run_cmd(
            "toprf-node", image,
            args=[
                "--port 3001",
                "--coordinator-config /etc/toprf/coordinator.json",
            ],
            env={
                "SEALED_KEY_URL": staging_sealed_url,
                "EXPECTED_VERIFICATION_SHARE": vs,
                "EXPECTED_PEER_MEASUREMENT": measurement,
                "AMD_ARK_FINGERPRINT": ark_fingerprint,
            },
            volumes=[
                "/etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro",
            ],
            port=3001,
        )
        run_ssm_command(
            region, staging_id,
            [
                "mkdir -p /etc/toprf",
                f"cat > /etc/toprf/coordinator.json << 'COORD_EOF'\n"
                f"{coord_config}\nCOORD_EOF",
                node_cmd,
            ],
            comment=f"Start node-{node_id} normal mode",
        )

        # Health check via SSM
        if not check_staging_health_via_ssm(region, staging_id):
            raise TimeoutError(
                "Staging node not healthy after starting normal mode"
            )

        # ── Step 9: Swap NLB targets ──
        logger.info("Step 9: Swapping NLB targets")

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

        # ── Step 10: Finalize ──
        logger.info("Step 10: Finalizing")

        # Terminate old instance
        if old_instance:
            terminate_instance(region, old_instance)

        # Retag staging -> permanent
        retag_instance(region, staging_id, f"toprf-node-{node_id}")

        # Copy sealed blob: staging -> canonical, then delete staging
        s3.copy_object(
            Bucket=bucket,
            Key=canonical_sealed_key,
            CopySource={"Bucket": bucket, "Key": staging_sealed_key},
        )
        try:
            s3.head_object(Bucket=bucket, Key=canonical_sealed_key)
            s3.delete_object(Bucket=bucket, Key=staging_sealed_key)
            logger.info(
                f"Sealed blob renamed: "
                f"{staging_sealed_key} -> {canonical_sealed_key}"
            )
        except ClientError:
            logger.warning(
                "Could not verify sealed blob copy — "
                "keeping staging blob as backup"
            )

        # Restart container with canonical sealed URL
        node_cmd_canonical = _build_docker_run_cmd(
            "toprf-node", image,
            args=[
                "--port 3001",
                "--coordinator-config /etc/toprf/coordinator.json",
            ],
            env={
                "SEALED_KEY_URL": canonical_sealed_url,
                "EXPECTED_VERIFICATION_SHARE": vs,
                "EXPECTED_PEER_MEASUREMENT": measurement,
                "AMD_ARK_FINGERPRINT": ark_fingerprint,
            },
            volumes=[
                "/etc/toprf/coordinator.json:/etc/toprf/coordinator.json:ro",
            ],
            port=3001,
        )
        run_ssm_command(
            region, staging_id,
            [
                "docker rm -f toprf-node 2>/dev/null || true",
                node_cmd_canonical,
            ],
            comment=f"Restart node-{node_id} with canonical sealed URL",
        )

        # Verify health after restart
        if not check_staging_health_via_ssm(region, staging_id):
            logger.warning(
                "Node not healthy after restart — may need manual check"
            )

        # Update SSM config with new instance info
        update_node_config(config, node_id, {
            "instance_id": staging_id,
            "private_ip": staging_ip,
        })

        # Clean up
        cleanup_reshare_artifacts(bucket, region)

        logger.info(f"=== Node {node_id} rotation complete ===")
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
