#!/usr/bin/env python3
"""
Control: KMS key does not grant access to everyone via its key policy
(i.e. Principal "*" / {"AWS": "*"} without a restricting Condition).

Requires: pip install boto3 tqdm --break-system-packages

Usage:
    python kms_key_not_publicly_accessible_aws.py -R arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
    python kms_key_not_publicly_accessible_aws.py -R arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME> --regions us-east-1 us-west-2

Assumes the given IAM role via STS, then checks every customer-managed KMS
key (AWS-managed keys are skipped, since you can't change their policy) in
every enabled region and verifies its key policy does not grant kms:* (or
any) permissions to Principal "*" / {"AWS": "*"} without a Condition that
restricts access (e.g. kms:CallerAccount, aws:PrincipalAccount, aws:SourceArn).
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    print(
        "\nERROR: The 'boto3' package is not installed in this Python environment.\n"
        "Fix with:\n"
        "    pip install boto3 --break-system-packages\n"
    )
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print(
        "\nERROR: The 'tqdm' package is not installed in this Python environment.\n"
        "Fix with:\n"
        "    pip install tqdm --break-system-packages\n"
    )
    sys.exit(1)


# ==================================================
# AUTH
# ==================================================
def assume_role(role_arn, session_name="kms-public-access-audit"):
    """Assumes the given IAM role via STS and returns a boto3 Session."""
    sts = boto3.client("sts")
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# ==================================================
# REGIONS
# ==================================================
def get_regions(session, requested_regions=None):
    """Returns the list of regions to scan (enabled regions, or a filtered subset)."""
    ec2 = session.client("ec2", region_name="us-east-1")
    all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
    if requested_regions:
        return [r for r in all_regions if r in requested_regions]
    return all_regions


# ==================================================
# HELPERS
# ==================================================
def error_evidence(e):
    """Classify a boto3 ClientError into a short code + human-readable evidence string."""
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "ClientError")
        message = e.response.get("Error", {}).get("Message", str(e))
    else:
        code = e.__class__.__name__
        message = str(e)
    return code, f"{code}: {message}"[:200]


def statement_is_public(statement):
    """
    Returns True if a single policy statement grants access to everyone
    (Principal '*' or {"AWS": "*"}) without a Condition narrowing it down.
    """
    if statement.get("Effect") != "Allow":
        return False

    principal = statement.get("Principal")
    is_wildcard_principal = (
        principal == "*"
        or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
    )
    if not is_wildcard_principal:
        return False

    # A Condition block (e.g. restricting by kms:CallerAccount,
    # aws:PrincipalAccount, aws:SourceArn, aws:SourceAccount) means the
    # wildcard principal is actually scoped down, not truly public.
    if statement.get("Condition"):
        return False

    return True


def find_public_statements(policy_doc):
    """Returns a list of 'Sid/Action -> Principal' finding strings for public statements."""
    findings = []
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if statement_is_public(stmt):
            sid = stmt.get("Sid", "NoSid")
            actions = stmt.get("Action", "N/A")
            if isinstance(actions, list):
                actions = ",".join(actions)
            findings.append(f"Sid={sid} Action={actions} Principal=*")
    return findings


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, regions):
    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        kms = session.client("kms", region_name=region)

        try:
            paginator = kms.get_paginator("list_keys")
            keys = []
            for page in paginator.paginate():
                keys.extend(page["Keys"])
        except (ClientError, BotoCoreError) as e:
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
            key_id = key["KeyId"]
            key_arn = key["KeyArn"]

            try:
                describe = kms.describe_key(KeyId=key_id)
                key_metadata = describe["KeyMetadata"]
            except (ClientError, BotoCoreError) as e:
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

            # Skip AWS-managed keys (aws/*) - you cannot edit their policy,
            # and they are not customer-controlled resources.
            if key_metadata.get("KeyManager") == "AWS":
                continue

            total_checked += 1

            try:
                policy_resp = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                policy_doc = json.loads(policy_resp["Policy"])
            except (ClientError, BotoCoreError) as e:
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

            findings = find_public_statements(policy_doc)

            if not findings:
                status = "COMPLIANT"
                compliant += 1
                evidence = "No key policy statements grant access to Principal '*' without a restricting Condition"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = "; ".join(findings)

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
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"kms_key_not_publicly_accessible_{account_id}_{timestamp}.csv"

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
        description="Check AWS KMS keys do not grant public access (Principal '*') via their key policy."
    )
    parser.add_argument("-R", "--role-arn", required=True, help="IAM Role ARN to assume, e.g. arn:aws:iam::123456789012:role/MyRole")
    parser.add_argument("--regions", nargs="*", default=None, help="Optional list of regions to scan (default: all enabled regions)")
    args = parser.parse_args()

    account_id = args.role_arn.split(":")[4]

    session = assume_role(args.role_arn)
    regions = get_regions(session, args.regions)

    control_name = "KMS - Key Does Not Grant Public Access via Key Policy"

    results, total_checked, compliant, non_compliant, skipped = check_control(session, regions)

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
