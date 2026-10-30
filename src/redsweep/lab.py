"""The live lab: real commands, real state changes, real rollbacks, all on this machine, against a small throwaway web app that
Redsweep starts on 127.0.0.1. Nothing leaves your computer. It checks that the tool really catches what it says it catches."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .cli import main as cli_main


def _make_handler(root: Path):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=""):
            b = body.encode()
            self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            p = urlparse(self.path).path
            if p == "/config":
                return self._send(200, (root / "app_config.ini").read_text())
            if p == "/claims/1":
                return self._send(200, (root / "claims.json").read_text())
            self._send(404, "not found")

        def do_POST(self):
            u = urlparse(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
            if u.path == "/config":  # change one setting
                k, _, v = body.partition("=")
                lines = [(f"{k}={v}" if l.startswith(k + "=") else l) for l in (root / "app_config.ini").read_text().splitlines()]
                (root / "app_config.ini").write_text("\n".join(lines) + "\n")
                return self._send(200, "ok")
            if u.path == "/users":  # a new user also gets a group line: two files change
                with open(root / "users.txt", "a") as f:
                    f.write(body + "\n")
                with open(root / "groups.txt", "a") as f:
                    f.write(f"{body}:analysts\n")
                return self._send(200, "ok")
            if u.path == "/upload":
                name = Path(parse_qs(u.query).get("name", ["x"])[0]).name
                (root / "uploads" / name).write_text(body)
                return self._send(200, "ok")
            self._send(404, "not found")
    return H


class Lab:
    def __init__(self, directory):
        self.dir = Path(directory).resolve()
        self.log, self.fail = [], 0
        self.checks = 0

    def L(self, *argv, expect=0, show=True):
        buf = io.BytesIO()
        w = io.TextIOWrapper(buf, encoding="utf-8", write_through=True)
        with contextlib.redirect_stdout(w), contextlib.redirect_stderr(w):
            code = cli_main(list(argv))
        out = buf.getvalue().decode(errors="replace").rstrip()
        self.checks += 1
        ok = code == expect
        if show:
            print("$ redsweep " + " ".join(a if " " not in a else repr(a) for a in argv))
            for line in out.splitlines()[:12]:
                print("  " + line)
            if len(out.splitlines()) > 12:
                print(f"  … ({len(out.splitlines()) - 12} more lines)")
            print(f"  [exit {code}]" + ("" if ok else f"   <-- LAB EXPECTED {expect}"))
        if not ok:
            self.fail += 1
        return out, code


def run_lab(directory, keep=False):
    lab = Lab(directory)
    root = lab.dir / "target"
    if lab.dir.exists():
        shutil.rmtree(lab.dir)
    (root / "uploads").mkdir(parents=True)
    (root / "app_config.ini").write_text("[app]\nexport_limit=100\ndebug=false\n")
    (root / "users.txt").write_text("analyst1\nanalyst2\n")
    (root / "groups.txt").write_text("analyst1:analysts\nanalyst2:analysts\n")
    (root / "crontab.txt").write_text("# lab job list\n0 3 * * * /usr/local/bin/backup\n")
    (root / "claims.json").write_text("{}")
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(root))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    os.environ["REDSWEEP_HOME"] = str(lab.dir / ".redsweep")
    os.environ["REDSWEEP_OPERATOR"] = "alice"
    curl = shutil.which("curl")
    if not curl:
        print("the lab needs curl (sudo apt install curl)")
        return 1
    print(f"Lab target: a small web app on {base}, files in {root}\n")
    L = lab.L
    L("init", "--name", "LAB-1", "--client", "this machine")
    sc = json.loads((lab.dir / ".redsweep" / "scope.json").read_text())
    sc.update({"engagement": "LAB-1", "in_scope": {"hosts": ["127.0.0.1", "localhost"]}, "out_of_scope": ["169.254.169.254"],
               "forbidden_actions": ["denial-of-service"], "roles": {"control_team": ["pat"], "red_lead": ["alice"]},
               "window": {"start": "2020-01-01T00:00:00Z", "end": "2099-12-31T23:59:59Z"}})
    (lab.dir / ".redsweep" / "scope.json").write_text(json.dumps(sc, indent=2))

    print("\n--- 1. The rules of engagement are enforced, not remembered")
    L("scope", "check", "127.0.0.1")
    L("scope", "check", "169.254.169.254", expect=1)
    L("wrap", "--host", "169.254.169.254", "--", curl, "-s", "http://169.254.169.254/", expect=1)
    L("wrap", "--host", "127.0.0.1", "--class", "network-logon", "--", curl, "-s", f"{base}/config")

    print("\n--- 2. Record BEFORE you change; Redsweep captures the original state itself")
    cfg, usr, upl, cron = (str(root / n) for n in ("app_config.ini", "users.txt", "uploads", "crontab.txt"))
    out, _ = L("change", "add", "--kind", "config", "--host", "127.0.0.1", "--object", "app setting export_limit", "--change", "100 -> 5000",
               "--capture", f"cat {cfg}", "--rollback-cmd", f"curl -s -X POST --data 'export_limit=100' {base}/config", show=False)
    c_cfg = out.split()[1].rstrip(".")
    out, _ = L("change", "add", "--kind", "account", "--host", "127.0.0.1", "--object", "user harbor-test-1", "--change", "create user",
               "--capture", f"cat {usr} {root / 'groups.txt'}",
               "--rollback-cmd", f"sed -i '/harbor-test-1/d' {usr}")  # note: this rollback forgets groups.txt
    c_usr = out.split()[1].rstrip(".")
    out, _ = L("change", "add", "--kind", "file", "--host", "127.0.0.1", "--object", "uploads/probe.txt", "--change", "upload a test file",
               "--capture", f"ls -1 {upl}", "--rollback-cmd", f"rm -f {upl}/probe.txt", show=False)
    c_file = out.split()[1].rstrip(".")
    out, _ = L("change", "add", "--kind", "persistence", "--host", "127.0.0.1", "--object", "crontab.txt line", "--change", "add a job line",
               "--capture", f"cat {cron}", "--rollback-cmd", f"sed -i '/harbor-job/d' {cron}")
    c_cron = out.split()[1].rstrip(".")
    # now really make the changes, through the web app and on disk
    L("wrap", "--host", "127.0.0.1", "--", curl, "-s", "-X", "POST", "--data", "export_limit=5000", f"{base}/config", show=False)
    L("wrap", "--host", "127.0.0.1", "--", curl, "-s", "-X", "POST", "--data", "harbor-test-1", f"{base}/users", show=False)
    L("wrap", "--host", "127.0.0.1", "--", curl, "-s", "-X", "POST", "--data", "hello", f"{base}/upload?name=probe.txt", show=False)
    with open(cron, "a") as f:
        f.write("*/5 * * * * /tmp/harbor-job\n")
    L("log", "tried the analyst role on the claims app", "--host", "127.0.0.1", "--result", "fail", "--assumption", "role exists", "--layer", "authorization", show=False)
    L("log", "tried it again", "--host", "127.0.0.1", "--result", "fail", "--assumption", "role exists", "--layer", "authorization")
    L("close", "--check", expect=2)

    print("\n--- 3. A rollback that LOOKS done but is not, caught by the independent read-back")
    L("change", "rollback", c_usr, "--run", "--verify", expect=2)
    L("close", "--check", expect=2, show=False)
    (root / "groups.txt").write_text("analyst1:analysts\nanalyst2:analysts\n")  # the operator fixes the part the rollback forgot
    L("change", "verify", c_usr)
    L("change", "rollback", c_cfg, "--run", "--verify")
    L("change", "rollback", c_file, "--run", "--verify", show=False)

    print("\n--- 4. Credentials, canary proof, freeze and SITREP")
    secret = lab.dir / "k.txt"
    secret.write_text("lab-secret")
    L("cred", "add", "--family", "password", "--principal", "svc-claims-etl", "--material-file", str(secret), "--host", "127.0.0.1")
    kid = lab.L("cred", "list", show=False)[0].split()[0]
    L("cred", "step", kid, "1", "--note", "removed from notes"); L("cred", "step", kid, "2", "--note", "on the client rotation list")
    canary_out, _ = L("canary", "make", "--label", "claims-lab", show=False)
    rec = json.loads(canary_out[: canary_out.index("}") + 1])
    digest = canary_out.split("Digest of the record:")[1].strip()
    (root / "claims.json").write_text(json.dumps(rec))
    proof = lab.dir / "proof.json"
    L("wrap", "--host", "127.0.0.1", "--", curl, "-s", "-o", str(proof), f"{base}/claims/1", show=False)
    L("canary", "check", "--file", str(proof), "--expect", digest, "--label", "claims-lab")
    L("evidence", "add", str(proof), "--label", "claims canary read", "--ladder", "canary", "--host", "127.0.0.1")
    eid = lab.L("evidence", "list", show=False)[0].split()[0]
    L("detect", "L3", "--host", "127.0.0.1", "--source", "SOC", "--evidence", "incident opened")
    L("freeze", "--reason", "SOC incident opened")
    L("change", "add", "--kind", "file", "--host", "127.0.0.1", "--object", "x", "--change", "x", "--created", expect=1)  # refused while frozen
    alog = lab.L("log", "--list", show=False)[0].split()[0]
    L("sitrep", "--observed", "SOC opened an incident", "--ask", "continue or go dark?", "--based-on", alog)
    L("decide", "go-dark", "--by", "alice", "--why", "x", expect=1)  # the red lead may not decide
    dec, _ = L("decide", "go-dark", "--by", "pat", "--why", "measure the response", show=False)
    L("resume", "--approved-by", "pat")

    print("\n--- 5. Closeout refuses while anything is left behind")
    L("close", expect=2)
    L("change", "rollback", c_cron, "--run", "--verify")
    L("change", "list")
    L("evidence", "handoff", eid, "--to", "pat", "--purpose", "kept for the report")
    L("close")

    print("\n--- 6. The record cannot be quietly edited")
    j = lab.dir / ".redsweep" / "journal" / "alice.jsonl"
    original = j.read_text()
    j.write_text(original.replace("claims canary read", "nothing to see", 1))
    L("verify", expect=3)
    L("verify-pack", str(lab.dir / ".redsweep" / "reports" / "closeout-pack.zip"))
    j.write_text(original)
    L("verify")

    srv.shutdown()
    ok = lab.fail == 0
    print(f"\nLab result: {lab.checks} commands run, {lab.fail} unexpected results. " + ("Everything behaved as the tool promises." if ok else "SOMETHING IS WRONG; see the lines marked LAB EXPECTED."))
    print(f"Open the report: {lab.dir / '.redsweep' / 'reports' / 'closeout.html'}")
    if not keep and ok:
        print("(use --keep to keep the folder; it is kept either way so you can open the report)")
    return 0 if ok else 1
