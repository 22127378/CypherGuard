"""Replay sample events through wazuh-analysisd (logtest socket) and check rule IDs.

Runs inside the wazuh/wazuh-manager container with the embedded Python:
  /var/ossec/framework/python/bin/python3 /tests/logtest.py /tests/cases.json
"""
import json
import socket
import struct
import sys
import time

SOCK = "/var/ossec/queue/sockets/logtest"


def call(request: dict) -> dict:
    payload = json.dumps(request).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall(struct.pack("<I", len(payload)) + payload)
        size = struct.unpack("<I", s.recv(4))[0]
        buf = b""
        while len(buf) < size:
            buf += s.recv(size - len(buf))
    return json.loads(buf)


def wait_for_socket(timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(SOCK)
            return
        except OSError:
            time.sleep(1)
    sys.exit("logtest socket never came up")


def main(path):
    cases = json.load(open(path))["cases"]
    wait_for_socket()
    token = None
    failures = 0
    for case in cases:
        event = case["event"]
        params = {
            "event": event if isinstance(event, str) else json.dumps(event, separators=(",", ":")),
            "log_format": "syslog",
            "location": case["location"],
        }
        if token:
            params["token"] = token
        resp = call({
            "version": 1,
            "origin": {"name": "cipherguard-tests", "module": "framework"},
            "command": "log_processing",
            "parameters": params,
        })
        if resp.get("error"):
            print(f"ERROR {case['name']}: {resp}")
            failures += 1
            continue
        data = resp["data"]
        token = data.get("token", token)
        rule = data.get("output", {}).get("rule", {})
        rid, level = rule.get("id"), int(rule.get("level", 0))
        mitre = rule.get("mitre", {}).get("id", [])
        alert = data.get("alert", False)

        ok = True
        if "expect" in case and case["expect"] is None:
            ok = not alert
        elif "expect" in case:
            ok = rid == case["expect"] and alert
            if ok and case.get("mitre"):
                ok = case["mitre"] in mitre
        if "expect_not" in case:
            ok = ok and rid != case["expect_not"]

        status = "ok  " if ok else "FAIL"
        print(f"{status}  {case['name']:<60} rule={rid} level={level} mitre={','.join(mitre) or '-'}")
        failures += 0 if ok else 1

    print(f"\n{len(cases) - failures}/{len(cases)} cases passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main(sys.argv[1])
