#!/usr/bin/env python3
"""
Control: AWS KMS customer managed key is not scheduled for deletion.

Checks every KMS key in every enabled region and verifies that customer
managed keys (KeyManager == "CUSTOMER") are NOT in the "PendingDeletion"
state. Any other key state (Enabled, Disabled, PendingImport, etc.) is
considered compliant for this control - only an active, irreversible
deletion countdown is flagged.

AWS managed keys (KeyManager == "AWS") are out of scope for this control
and are marked as not applicable.
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


NON_COMPLIANT_STATE = "PendingDeletion"


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

            total_checked += 1
            key_state = detail.get("KeyState", "Unknown")

            if key_state == NON_COMPLIANT_STATE:
                status = "NON_COMPLIANT"
                non_compliant += 1
                deletion_date = detail.get("DeletionDate")
                deletion_note = f", scheduled deletion date: {deletion_date}" if deletion_date else ""
                evidence = f"Key is scheduled for deletion (state: PendingDeletion{deletion_note})"
            else:
                status = "COMPLIANT"
                compliant += 1
                evidence = f"Key is not scheduled for deletion (current state: {key_state})"

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
    filename = f"kms_cmk_not_pending_deletion_{account_id}_{timestamp}.csv"

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
        description="Check KMS customer managed keys are not scheduled for deletion."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "KMS - Customer Managed Key Is Not Scheduled for Deletion"

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