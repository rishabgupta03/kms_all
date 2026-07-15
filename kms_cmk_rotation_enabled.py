#!/usr/bin/env python3
"""
Control: KMS customer-managed symmetric CMK has automatic rotation enabled.

Checks every KMS key in every enabled region and verifies that customer
managed, symmetric encryption keys (KeyManager == "CUSTOMER",
KeySpec == "SYMMETRIC_DEFAULT", KeyUsage == "ENCRYPT_DECRYPT") have
automatic key rotation enabled.

Out of scope (marked as not applicable):
  - AWS managed keys
  - Asymmetric keys (RSA/ECC) - automatic rotation is not supported
  - HMAC keys - evaluated under a separate rotation model, not this control
"""

import boto3
import argparse
import csv
from datetime import datetime
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================
def error_evidence(e):
    """Classify a ClientError into a short code + human-readable evidence string."""
    code = e.response.get("Error", {}).get("Code", "UnknownError")
    msg = e.response.get("Error", {}).get("Message", str(e))
    return code, f"{code}: {msg}"[:200]


REQUIRED_KEY_SPEC = "SYMMETRIC_DEFAULT"
REQUIRED_KEY_USAGE = "ENCRYPT_DECRYPT"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            kms = session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")
            keys = []
            for page in paginator.paginate():
                keys.extend(page.get("Keys", []))
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            results.append({
                "Region": region,
                "KeyId": "N/A",
                "KeyArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        for key in keys:
            key_id = key.get("KeyId", "N/A")
            key_arn = key.get("KeyArn", "N/A")

            try:
                detail = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError as e:
                code, evidence = error_evidence(e)
                skipped += 1
                results.append({
                    "Region": region,
                    "KeyId": key_id,
                    "KeyArn": key_arn,
                    "Status": "SKIPPED",
                    "Evidence": evidence
                })
                continue

            key_manager = detail.get("KeyManager", "UNKNOWN")
            key_spec = detail.get("KeySpec", "UNKNOWN")
            key_usage = detail.get("KeyUsage", "UNKNOWN")
            key_state = detail.get("KeyState", "Unknown")

            # --- Only customer managed keys are in scope for this control ---
            if key_manager != "CUSTOMER":
                skipped += 1
                results.append({
                    "Region": region,
                    "KeyId": key_id,
                    "KeyArn": key_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"Not a customer managed key (KeyManager: {key_manager})"
                })
                continue

            # --- Only symmetric encryption keys support automatic rotation ---
            if key_spec != REQUIRED_KEY_SPEC or key_usage != REQUIRED_KEY_USAGE:
                skipped += 1
                results.append({
                    "Region": region,
                    "KeyId": key_id,
                    "KeyArn": key_arn,
                    "Status": "SKIPPED",
                    "Evidence": (
                        f"Automatic rotation not applicable "
                        f"(KeySpec: {key_spec}, KeyUsage: {key_usage})"
                    )
                })
                continue

            # --- Keys pending deletion can't have rotation meaningfully evaluated ---
            if key_state == "PendingDeletion":
                skipped += 1
                results.append({
                    "Region": region,
                    "KeyId": key_id,
                    "KeyArn": key_arn,
                    "Status": "SKIPPED",
                    "Evidence": "Key is pending deletion - rotation status not evaluated"
                })
                continue

            total_checked += 1

            try:
                rotation_status = kms.get_key_rotation_status(KeyId=key_id)
                rotation_enabled = rotation_status.get("KeyRotationEnabled", False)
            except ClientError as e:
                code, evidence = error_evidence(e)
                skipped += 1
                total_checked -= 1
                results.append({
                    "Region": region,
                    "KeyId": key_id,
                    "KeyArn": key_arn,
                    "Status": "SKIPPED",
                    "Evidence": evidence
                })
                continue

            if rotation_enabled:
                status = "COMPLIANT"
                compliant += 1
                period = rotation_status.get("RotationPeriodInDays")
                period_note = f" (rotation period: {period} days)" if period else ""
                evidence = f"Automatic key rotation is enabled{period_note}"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = "Automatic key rotation is not enabled"

            results.append({
                "Region": region,
                "KeyId": key_id,
                "KeyArn": key_arn,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"kms_cmk_rotation_enabled_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "KeyId", "KeyArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "KeyId": row["KeyId"],
                "KeyArn": row["KeyArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check KMS customer-managed symmetric CMKs have automatic rotation enabled."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "KMS - Customer-Managed Symmetric CMK Has Automatic Rotation Enabled"

    results, total_checked, compliant, non_compliant, skipped = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n====================================================")
    print(f"CONTROL: {control_name}")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("====================================================\n")


if __name__ == "__main__":
    main()