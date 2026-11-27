"""Offline checks for the GuardDuty auto-fix Lambda (no AWS calls).

boto3 is replaced by a fake IAM client that records calls, so the guards are
tested exactly as deployed:  python3 tests/lambda/test_autofix.py
"""
import os
import sys
import types


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeIAM:
    def __init__(self):
        self.calls = []

    def put_role_policy(self, RoleName, **_):
        self.calls.append(("quarantine", RoleName))

    def update_access_key(self, UserName, AccessKeyId, Status):
        if UserName == "cipherguard-ghost":
            raise ClientError("NoSuchEntity")
        self.calls.append(("disable", UserName, AccessKeyId, Status))


iam = FakeIAM()
sys.modules["boto3"] = types.SimpleNamespace(client=lambda _name: iam)
sys.modules["botocore"] = types.ModuleType("botocore")
sys.modules["botocore.exceptions"] = types.SimpleNamespace(ClientError=ClientError)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "infra", "terraform", "lambda"))
import autofix  # noqa: E402


def finding(user_type, name, key="AKIAEXAMPLE"):
    return {"detail": {"type": "T", "severity": 8, "resource": {"accessKeyDetails": {
        "userType": user_type, "userName": name, "accessKeyId": key}}}}


CASES = [
    ("lab role is quarantined", finding("AssumedRole", "cipherguard-demo-app"),
     [("quarantine", "cipherguard-demo-app")], "attached"),
    ("lab user key is disabled", finding("IAMUser", "cipherguard-leaky"),
     [("disable", "cipherguard-leaky", "AKIAEXAMPLE", "Inactive")], "deactivated"),
    ("operator user is never touched", finding("IAMUser", "cipherguard-admin"), [], "skip user"),
    ("other users are never touched", finding("IAMUser", "alice"), [], "skip user"),
    ("GuardDuty sample user is skipped", finding("IAMUser", "GeneratedFindingUserName"), [], "skip user"),
    ("pipeline role is never touched", finding("AssumedRole", "cipherguard-gha-apply"), [], "skip role"),
    ("cluster-admin role is never touched", finding("AssumedRole", "cipherguard-cluster-admin"), [], "skip role"),
    ("missing user does not crash", finding("IAMUser", "cipherguard-ghost"), [], "failed to deactivate"),
]

failures = 0
for name, event, want_calls, want_text in CASES:
    iam.calls.clear()
    try:
        out = autofix.handler(event, None)
        text = " ".join(out["actions"])
        ok = iam.calls == want_calls and want_text in text
    except Exception as e:  # any exception is a failed invocation in Lambda
        ok, text = False, f"raised {type(e).__name__}: {e}"
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} autofix: {name}" + ("" if ok else f" -> calls={iam.calls} {text}"))

sys.exit(f"{failures} auto-fix check(s) failed" if failures else 0)
