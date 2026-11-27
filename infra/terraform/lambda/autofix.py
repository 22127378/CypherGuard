"""CipherGuard cloud auto-fix (scenario I/D prevention).

Triggered by EventBridge on high-severity GuardDuty findings. It contains the
compromised credential:

  - an assumed-role (e.g. node credentials used off-box): attach a Deny-all
    inline policy to the role, which neutralises the stolen session immediately
    (IAM evaluates policy in real time);
  - an IAM user access key flagged in the finding: deactivate the key.

Guards: it only ever touches roles and users named cipherguard-*, and never
the pipeline roles (cipherguard-gha-*), its own role (cipherguard-autofix) or
the operator principals (cipherguard-admin, cipherguard-cluster-admin). Found
live: the key path had no guard, so a high-severity finding (even a false
positive or a GuardDuty sample) naming any IAM user would deactivate that
user's key, including the operator's own. Set CG_DRYRUN=1 to log intended
actions without making changes.
"""
import json
import os
import re

import boto3
from botocore.exceptions import ClientError

iam = boto3.client("iam")

DRYRUN = os.environ.get("CG_DRYRUN") == "1"
ALLOWED = re.compile(r"^cipherguard-")
PROTECTED = re.compile(r"^cipherguard-(gha-|autofix|admin$|cluster-admin$)")
QUARANTINE = "CipherGuardQuarantine"
DENY_ALL = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "Quarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}],
}


def _may_touch(role: str) -> bool:
    return bool(role) and ALLOWED.match(role) and not PROTECTED.match(role)


def quarantine_role(role: str) -> str:
    if not _may_touch(role):
        return f"skip role {role} (not an in-scope lab role)"
    if DRYRUN:
        return f"[dry-run] would attach {QUARANTINE} deny policy to {role}"
    try:
        iam.put_role_policy(
            RoleName=role, PolicyName=QUARANTINE, PolicyDocument=json.dumps(DENY_ALL)
        )
    except ClientError as e:
        return f"failed to quarantine role {role}: {e.response['Error']['Code']}"
    return f"attached {QUARANTINE} deny policy to {role}"


def disable_key(user: str, key_id: str) -> str:
    if not key_id:
        return "no access key in finding"
    if not _may_touch(user):
        return f"skip user {user} (not an in-scope lab user)"
    if DRYRUN:
        return f"[dry-run] would deactivate access key {key_id} of {user}"
    try:
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    except ClientError as e:
        # Found live: a GuardDuty sample finding names a user that does not
        # exist, and the uncaught error failed the invocation.
        return f"failed to deactivate key {key_id} of {user}: {e.response['Error']['Code']}"
    return f"deactivated access key {key_id} of {user}"


def handler(event, _context):
    detail = event.get("detail", {})
    ftype = detail.get("type", "unknown")
    severity = detail.get("severity", 0)
    access = (
        detail.get("resource", {}).get("accessKeyDetails", {}) if isinstance(detail.get("resource"), dict) else {}
    )
    user_type = access.get("userType", "")
    name = access.get("userName", "")  # role name for AssumedRole, user name for IAMUser
    key_id = access.get("accessKeyId", "")

    actions = []
    # Act on the principal type the finding names: a role for an assumed-role
    # session, a key for an IAM user. (A prior version also treated any
    # cipherguard-* IAM user as a role and tried to quarantine it.)
    if user_type == "AssumedRole":
        actions.append(quarantine_role(name))
    if user_type == "IAMUser":
        actions.append(disable_key(name, key_id))
    if not actions:
        actions.append(f"no in-scope principal in finding ({user_type or 'n/a'})")

    result = {"finding": ftype, "severity": severity, "principal": name, "actions": actions}
    print(json.dumps(result))
    return result
