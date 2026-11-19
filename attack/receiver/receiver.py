#!/usr/bin/env python3
"""Lab-only HTTP receiver for the CipherGuard exfiltration simulation.

Accepts POST bodies (the encrypted synthetic payload) and stores them with a
timestamp. It never decrypts anything; it only proves the data left the pod.
"""
import argparse
import datetime
import http.server
import json
import pathlib

MAX_BODY = 5 * 1024 * 1024  # 5 MB is plenty for synthetic test data


def make_handler(out_dir: pathlib.Path):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > MAX_BODY:
                self.send_error(413, "Body missing or too large")
                return
            body = self.rfile.read(length)
            ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            (out_dir / f"{ts}.bin").write_bytes(body)
            (out_dir / f"{ts}.json").write_text(json.dumps({
                "received_at": ts,
                "source": self.client_address[0],
                "path": self.path,
                "bytes": length,
            }))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"receiver up\n")

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--out", default="/var/lib/receiver")
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(out_dir))
    server.serve_forever()


if __name__ == "__main__":
    main()
