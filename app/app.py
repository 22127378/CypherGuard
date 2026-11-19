"""CipherGuard demo app: the attack target.

Small on purpose. It reads one SSM parameter through its IRSA role so the smoke
test can prove pod -> AWS access works without static keys.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3

PARAM_NAME = os.environ.get("GREETING_PARAM", "/cipherguard/demo-app/greeting")
PORT = int(os.environ.get("PORT", "8080"))
REGION = os.environ.get("AWS_REGION", "ap-southeast-1")

_ssm = None


def greeting() -> str:
    global _ssm
    if _ssm is None:
        _ssm = boto3.client("ssm", region_name=REGION)
    return _ssm.get_parameter(Name=PARAM_NAME, WithDecryption=True)["Parameter"]["Value"]


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        elif self.path == "/":
            try:
                self._send(200, {"greeting": greeting()})
            except Exception as exc:  # surface IRSA problems in the smoke test
                self._send(502, {"error": type(exc).__name__})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print(json.dumps({"client": self.client_address[0], "request": fmt % args}), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
