#!/usr/bin/env python3
"""
Control: Cloud KMS key does not grant access to allUsers or
allAuthenticatedUsers.

NOTE: This is a Google Cloud Platform control (Cloud KMS), not AWS. It uses
a different SDK (google-cloud-kms) and a different auth model
(service account credentials / Application Default Credentials instead of
IAM role assumption), since GCP has no equivalent of an AWS IAM role ARN or
STS AssumeRole. The overall script shape (AUTH / LOCATIONS / HELPERS /
CONTROL LOGIC / CSV / MAIN, counters, tqdm, CLI summary block) mirrors your
AWS scripts as closely as GCP's APIs allow.

Requires: pip install google-cloud-kms --break-system-packages

Usage:
    python kms_key_not_publicly_accessible.py -P your-gcp-project-id
    python kms_key_not_publicly_accessible.py -P your-gcp-project-id -C /path/to/service-account.json

Checks every Cloud KMS CryptoKey in every location in the given project and
verifies that its IAM policy does not grant any role to the special members
"allUsers" (public/anonymous internet access) or "allAuthenticatedUsers"
(any authenticated Google account, i.e. effectively public).
"""

import argparse
import csv
import sys
from datetime import datetime, timezone

# ==================================================
# DEPENDENCY CHECK (fail fast with a clear message instead of a raw
# traceback if google-cloud-kms isn't installed in this environment)
# ==================================================
try:
    from tqdm import tqdm
except ImportError:
    print(
        "\nERROR: The 'tqdm' package is not installed in this Python environment.\n"
        "Fix with:\n"
        "    pip install tqdm --break-system-packages\n"
    )
    sys.exit(1)

try:
    from google.cloud import kms_v1
    from google.oauth2 import service_account
    from google.api_core.exceptions import GoogleAPICallError
except ImportError:
    print(
        "\nERROR: The 'google-cloud-kms' package is not installed (or not installed\n"
        "in the Python interpreter currently running this script).\n\n"
        "Fix with:\n"
        "    pip install google-cloud-kms --break-system-packages\n\n"
        "If it's already installed but this still fails, you likely have a stale\n"
        "or conflicting 'google.cloud' namespace package. Clear it with:\n"
        "    pip uninstall -y google-cloud-kms google-api-core google-cloud-core --break-system-packages\n"
        "    pip install --upgrade google-cloud-kms --break-system-packages\n\n"
        "Verify the fix with:\n"
        "    python3 -c \"from google.cloud import kms_v1; print(kms_v1.__file__)\"\n"
        "(it should print a real file path, not '(unknown location)')\n"
    )
    sys.exit(1)


# ==================================================
# AUTH
# ==================================================
def get_client(credentials_file=None):
    """
    Returns a KeyManagementServiceClient.
    If --credentials-file is provided, uses that service account key.
    Otherwise falls back to Application Default Credentials (e.g. a
    GOOGLE_APPLICATION_CREDENTIALS env var, gcloud auth application-default
    login, or attached workload identity).
    """
    if credentials_file:
        creds = service_account.Credentials.from_service_account_file(
            credentials_file,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        return kms_v1.KeyManagementServiceClient(credentials=creds)
    return kms_v1.KeyManagementServiceClient()


# ==================================================
# LOCATIONS
# ==================================================
def get_locations(client, project_id):
    """Returns all Cloud KMS locations available to this project."""
    locations = []
    request = {"name": f"projects/{project_id}"}
    for location in client.list_locations(request=request):
        locations.append(location.location_id)
    return locations


# ==================================================
# HELPERS
# ==================================================
def error_evidence(e):
    """Classify a GoogleAPICallError into a short code + human-readable evidence string."""
    code = getattr(e, "reason", None) or e.__class__.__name__
    message = getattr(e, "message", str(e))
    return code, f"{code}: {message}"[:200]


PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def find_public_grants(policy):
    """
    Returns a list of 'role -> member' finding strings for any binding that
    grants access to allUsers or allAuthenticatedUsers.
    """
    findings = []
    for binding in policy.bindings:
        role = binding.role
        for member in binding.members:
            if member in PUBLIC_MEMBERS:
                findings.append(f"{role} granted to {member}")
    return findings


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(client, project_id):
    locations = get_locations(client, project_id)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nLocations to Scan: {len(locations)}\n")

    for location in tqdm(locations, desc="Scanning Locations"):
        location_parent = f"projects/{project_id}/locations/{location}"

        try:
            key_rings = list(client.list_key_rings(request={"parent": location_parent}))
        except GoogleAPICallError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            results.append({
                "Location": location,
                "KeyRing": "N/A",
                "CryptoKeyName": "N/A",
                "ResourceName": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        for key_ring in key_rings:
            key_ring_short_name = key_ring.name.split("/")[-1]

            try:
                crypto_keys = list(client.list_crypto_keys(request={"parent": key_ring.name}))
            except GoogleAPICallError as e:
                code, evidence = error_evidence(e)
                skipped += 1
                results.append({
                    "Location": location,
                    "KeyRing": key_ring_short_name,
                    "CryptoKeyName": "N/A",
                    "ResourceName": key_ring.name,
                    "Status": "SKIPPED",
                    "Evidence": evidence
                })
                continue

            for crypto_key in crypto_keys:
                total_checked += 1
                key_short_name = crypto_key.name.split("/")[-1]
                # Include the key ring in the resource identifier so two keys
                # with the same short name in different key rings aren't
                # conflated in the report.
                resource_uid = f"{key_ring_short_name}/{key_short_name}"

                try:
                    policy = client.get_iam_policy(request={"resource": crypto_key.name})
                except GoogleAPICallError as e:
                    code, evidence = error_evidence(e)
                    skipped += 1
                    total_checked -= 1
                    results.append({
                        "Location": location,
                        "KeyRing": key_ring_short_name,
                        "CryptoKeyName": resource_uid,
                        "ResourceName": crypto_key.name,
                        "Status": "SKIPPED",
                        "Evidence": evidence
                    })
                    continue

                findings = find_public_grants(policy)

                if not findings:
                    status = "COMPLIANT"
                    compliant += 1
                    evidence = "No IAM bindings grant access to allUsers or allAuthenticatedUsers"
                else:
                    status = "NON_COMPLIANT"
                    non_compliant += 1
                    evidence = "; ".join(findings)

                results.append({
                    "Location": location,
                    "KeyRing": key_ring_short_name,
                    "CryptoKeyName": resource_uid,
                    "ResourceName": crypto_key.name,
                    "Status": status,
                    "Evidence": evidence
                })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, project_id):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"gcp_kms_no_public_access_{project_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Project", "Location", "KeyRing", "CryptoKeyName", "ResourceName", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Project": project_id,
                "Location": row["Location"],
                "KeyRing": row["KeyRing"],
                "CryptoKeyName": row["CryptoKeyName"],
                "ResourceName": row["ResourceName"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check Cloud KMS keys do not grant access to allUsers or allAuthenticatedUsers."
    )
    parser.add_argument("-P", "--project", required=True, help="GCP Project ID to audit")
    parser.add_argument(
        "-C", "--credentials-file",
        help="Path to a service account JSON key file. If omitted, uses Application Default Credentials.",
        default=None
    )
    args = parser.parse_args()

    client = get_client(args.credentials_file)

    control_name = "Cloud KMS - Key Does Not Grant Access to allUsers or allAuthenticatedUsers"

    results, total_checked, compliant, non_compliant, skipped = check_control(client, args.project)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, args.project)

    print("\n====================================================")
    print(f"CONTROL: {control_name}")
    print(f"PROJECT: {args.project}")
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
