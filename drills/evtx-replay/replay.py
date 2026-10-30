"""Replay REAL Windows Security events from a public sample set against Redsweep's purple review.

The blue side is real: three small .evtx files from the public EVTX-ATTACK-SAMPLES repository (github.com/sbousseaden/EVTX-ATTACK-SAMPLES,
GPL-3.0). They are fetched when you run this script and are not copied into Redsweep. The operator side is SYNTHETIC: a short log written to line
up with those real events, because no public operator logs exist for them. Nothing here ran on GOAD.

Needs: git, and `pip install evtx` (a separate package; Redsweep itself has no dependencies).
Usage: python replay.py [WORKDIR]"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES"
FILES = ["Defense Evasion/DE_Fake_ComputerAccount_4720.evtx",
         "Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx",
         "Discovery/discovery_local_user_or_group_windows_security_4799_4798.evtx"]
W = Path(sys.argv[1] if len(sys.argv) > 1 else Path(tempfile.gettempdir()) / "redsweep-evtx-replay").resolve()
HOME = W / ".redsweep"

# Synthetic operator log, timed to the real events (UTC). host = the computer name the real events carry.
OPS = [
    ("2020-09-16T09:31:15Z", "alpha", "01566s-win16-ir.threebeesco.com", "user-add", "ok", "create a test computer account"),
    ("2020-09-16T09:32:10Z", "alpha", "01566s-win16-ir.threebeesco.com", "user-add", "ok", "create a second test computer account"),
    ("2020-09-16T09:45:00Z", "bravo", "01566s-win16-ir.threebeesco.com", "ldap-bulk-query", "ok", "read the directory account list"),
    ("2020-09-09T13:18:21Z", "alpha", "msedgewin10", "network-logon", "fail", "one logon with a wrong password (a deliberate test of alerting)"),
    ("2020-09-09T13:18:26Z", "alpha", "msedgewin10", "network-logon", "ok", "log on at the console"),
    ("2019-08-05T09:24:50Z", "bravo", "msedgewin10", "powershell", "ok", "list local users and groups"),
]


def lt(op, *args):
    env = dict(os.environ, REDSWEEP_HOME=str(HOME), REDSWEEP_OPERATOR=op, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-m", "redsweep", *args], env=env, capture_output=True, text=True, encoding="utf-8")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def fetch(dest):
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout", REPO, str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "sparse-checkout", "init", "--no-cone"], check=True)
    subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *["/" + f for f in FILES]], check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q"], check=True)


def field(data, *names):
    for n in names:
        v = data.get(n)
        if v not in (None, "", "-"):
            return str(v)
    return "?"


def to_blue(evtx_files, out_csv):
    from evtx import PyEvtxParser  # pip install evtx
    rows = []
    for f in evtx_files:
        for rec in PyEvtxParser(str(f)).records_json():
            ev = json.loads(rec["data"])["Event"]
            sy, data = ev["System"], ev.get("EventData") or {}
            eid = sy["EventID"]["#text"] if isinstance(sy["EventID"], dict) else sy["EventID"]
            t = sy["TimeCreated"]["#attributes"]["SystemTime"][:19] + "Z"
            who = field(data, "TargetUserName", "SamAccountName")
            extra = f", logon type {data['LogonType']}" if "LogonType" in data else ""
            rows.append([t, sy["Computer"].lower(), f"Security-{eid}", f"event {eid} (account: {who}{extra})", "L0"])  # raw telemetry: nobody looked
    rows.sort()
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["time", "host", "source", "summary", "level"]); w.writerows(rows)
    return rows


def main():
    if W.exists():
        shutil.rmtree(W)
    W.mkdir(parents=True)
    print("fetching three small .evtx files from the public sample repository ...")
    fetch(W / "evtx")
    rows = to_blue([W / "evtx" / f for f in FILES], W / "blue-timeline.csv")
    print(f"converted {len(rows)} real Windows Security events to blue-timeline.csv")
    with open(W / "operator-log.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["time", "operator", "host", "class", "result", "text"]); w.writerows(OPS)
    lt("alpha", "init", "--name", "EVTX-REPLAY", "--client", "public sample events")
    (HOME / "scope.json").write_text('{"engagement":"EVTX-REPLAY","window":{"start":"2019-01-01T00:00:00Z","end":"2027-12-31T23:59:59Z"},'
                                     '"in_scope":{"hosts":["*"],"cloud_projects":[],"accounts":[]},"out_of_scope":[],"forbidden_actions":[],"roles":{},"tripwires":[]}')
    maps = [x for k in ("time", "text", "host", "result", "class", "operator") for x in ("--map", f"{k}={k}")]
    rc, o = lt("alpha", "import", "csv", str(W / "operator-log.csv"), *maps)
    print(o.strip())
    rc2, o = lt("alpha", "review", str(W / "blue-timeline.csv"), "--window", "5")
    (W / "review.txt").write_text(o)
    print(o)
    ok = rc == 0 and rc2 == 0 and "5 of 6 actions were seen" in o
    print("REPLAY RESULT:", "as expected (5 of 6 actions seen)" if ok else "UNEXPECTED, see above")
    print(f"replay folder: {W}")
    return 0 if ok else 1


sys.exit(main())
