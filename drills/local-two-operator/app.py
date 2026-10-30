"""A tiny stand-in application for the drill: a real HTTP service with a config file and a user list.
Usage: python3 app.py DATA_DIR BIND_IP PORT"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

root = Path(sys.argv[1])


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=""):
        b = body.encode()
        self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path == "/config":
            return self._send(200, (root / "app.ini").read_text())
        if self.path == "/users":
            return self._send(200, (root / "users.txt").read_text())
        self._send(404, "not found")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode().strip()
        if self.path == "/config":
            k, _, v = body.partition("=")
            lines = [(f"{k}={v}" if l.startswith(k + "=") else l) for l in (root / "app.ini").read_text().splitlines()]
            (root / "app.ini").write_text("\n".join(lines) + "\n")
            return self._send(200, "ok")
        if self.path == "/users":
            with open(root / "users.txt", "a") as f:
                f.write(body + "\n")
            return self._send(200, "ok")
        self._send(404, "not found")


HTTPServer((sys.argv[2], int(sys.argv[3])), H).serve_forever()
