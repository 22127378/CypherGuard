"""End-to-end check of the Active Response script against a REAL Wazuh alert.

The alert is produced by wazuh-analysisd (logtest) from a Falco event, so its
JSON shape is exactly what wazuh-execd hands the script on a node. A stub `ctr`
on PATH records what the script would kill. Found live: Wazuh nests dotted
Falco keys (container.id -> container: {id}), which a hand-written fixture
did not reproduce.

Runs inside the wazuh/wazuh-manager container after logtest.py:
  /var/ossec/framework/python/bin/python3 /tests/ar_test.py
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logtest  # noqa: E402

SCRIPT = "/var/ossec/active-response/bin/cipherguard-isolate.sh"

FALCO_EVENT = {
    "hostname": "ip-10-20-1-23",
    "output": "Critical Escape tooling in container",
    "priority": "Critical",
    "rule": "CipherGuard Escape Tooling In Container",
    "source": "syscall",
    "tags": ["cipherguard", "container", "T1611"],
    "time": "2026-11-26T07:10:00.000000000Z",
    "output_fields": {
        "container.id": "3f2a9c1b7d10",
        "k8s.ns.name": "demo",
        "k8s.pod.name": "demo-app-7c9d8-abcde",
        "proc.name": "nsenter",
        "proc.cmdline": "nsenter -t 1 -m -u -i -n sh",
    },
}


def real_alert() -> dict:
    resp = logtest.call({
        "version": 1,
        "origin": {"name": "cipherguard-ar-test", "module": "framework"},
        "command": "log_processing",
        "parameters": {
            "event": json.dumps(FALCO_EVENT, separators=(",", ":")),
            "log_format": "syslog",
            "location": "/var/log/falco/events.json",
        },
    })
    out = resp["data"]["output"]
    assert out["rule"]["id"] == "100114", out["rule"]["id"]
    return out


def run(ar_input: dict, work: str) -> str:
    log = os.path.join(work, "ar.log")
    open(log, "w").close()
    env = dict(os.environ, CG_AR_LOG=log, PATH=f"{work}:{os.environ['PATH']}")
    subprocess.run(["bash", SCRIPT], input=json.dumps(ar_input).encode(), env=env, check=False)
    return open(log).read()


def main():
    logtest.wait_for_socket()
    alert = real_alert()
    failures = 0
    with tempfile.TemporaryDirectory() as work:
        # Stub ctr: list a full-length id for the short Falco id, log kills.
        stub = os.path.join(work, "ctr")
        with open(stub, "w") as fh:
            fh.write("#!/bin/bash\n"
                     "case \"$*\" in\n"
                     "  *'containers ls'*) echo 3f2a9c1b7d10aaaabbbbccccdddd ;;\n"
                     "  *'tasks kill'*) echo \"KILLED ${@: -1}\" ;;\n"
                     "esac\n")
        os.chmod(stub, 0o755)

        cases = [
            ("isolate (alert object)", {"command": "add", "parameters": {"alert": alert}},
             "stopped container 3f2a9c1b7d10aaaabbbbccccdddd"),
            ("isolate (alert as JSON string)",
             {"command": "add", "parameters": {"alert": json.dumps(alert)}},
             "stopped container 3f2a9c1b7d10aaaabbbbccccdddd"),
            ("delete is a no-op", {"command": "delete", "parameters": {"alert": alert}},
             "ignoring command=delete"),
        ]
        for name, ar_input, want in cases:
            got = run(ar_input, work)
            ok = want in got
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'} AR {name}" + ("" if ok else f": {got.strip()}"))

        # Malformed input must be reported, not swallowed.
        log = os.path.join(work, "ar.log")
        open(log, "w").close()
        env = dict(os.environ, CG_AR_LOG=log, PATH=f"{work}:{os.environ['PATH']}")
        subprocess.run(["bash", SCRIPT], input=b"not json", env=env, check=False)
        ok = "failed to parse AR input" in open(log).read()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} AR malformed input is logged")

    if failures:
        sys.exit(f"{failures} Active Response check(s) failed")
    print("Active Response checks passed")


if __name__ == "__main__":
    main()
