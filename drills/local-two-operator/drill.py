"""Two-operator drill that runs the same way on Linux and Windows. Everything stays on 127.0.0.x and inside one folder.
Usage: python drill.py [WORKDIR]"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
W = Path(sys.argv[1] if len(sys.argv) > 1 else Path(tempfile.gettempdir()) / "redsweep-drill").resolve()
PY = sys.executable
HOME = W / ".redsweep"
checks = []
procs = []


def q(p):
    return f'"{p}"'


def H(*args):  # a helper command line, usable inside capture and rollback commands
    return f'{q(PY)} {q(HERE / "helpers.py")} ' + " ".join(q(a) for a in args)


def lt(op, *args, show=True):
    env = dict(os.environ, REDSWEEP_HOME=str(HOME), REDSWEEP_OPERATOR=op, PYTHONIOENCODING="utf-8")
    p = subprocess.run([PY, "-m", "redsweep", *args], env=env, capture_output=True, text=True, encoding="utf-8")
    out = (p.stdout or "") + (p.stderr or "")
    if show and out.strip():
        print(out.rstrip())
    return p.returncode, out


A = lambda *a, **k: lt("alpha", *a, **k)   # red operator 1
B = lambda *a, **k: lt("bravo", *a, **k)   # red operator 2: does the read-backs
C = lambda *a, **k: lt("casey", *a, **k)   # Control Team


def ident(prefix, text):
    m = re.search(prefix + r"-[0-9a-f]{5}", text)
    return m.group(0) if m else ""


def step(t):
    print(f"\n=== {t}")


def expect(name, cond):
    checks.append((name, bool(cond)))
    print(f"  [{'ok' if cond else 'UNEXPECTED'}] {name}")


def start(*cmd, cwd=None):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    return p


def main():
    if W.exists():
        shutil.rmtree(W)
    (W / "app").mkdir(parents=True); (W / "files").mkdir()
    step("setup: engagement, scope, two operators and a Control Team")
    A("init", "--name", "DRILL-1", "--client", "Local drill", show=False)
    (HOME / "scope.json").write_text('''{"engagement":"DRILL-1","window":{"start":"2026-01-01T00:00:00Z","end":"2027-12-31T23:59:59Z"},
 "in_scope":{"hosts":["127.0.0.0/24"],"cloud_projects":[],"accounts":[]},"out_of_scope":["127.0.0.99"],
 "forbidden_actions":["denial-of-service"],"roles":{"control_team":["casey"],"red_lead":["alpha"]},"tripwires":["external_party"]}''')
    (HOME / "config.json").write_text('{"name":"DRILL-1","client":"Local drill","strict_scope":true,"require_second_operator":true,'
                                      '"min_verify_strength":"auto","assumption_stop_after":2,"sitrep_requires_log":true}')
    (W / "app" / "app.ini").write_text("mode=standard\nlimit=100\n")
    (W / "app" / "users.txt").write_text("")
    (W / "files" / "notes.txt").write_text("hello\n")
    start(PY, str(HERE / "app.py"), str(W / "app"), "127.0.0.11", "18080")
    for _ in range(100):  # let the app come up first, so starting it is not mistaken for activity
        if subprocess.run([PY, str(HERE / "helpers.py"), "probe", "127.0.0.11", "18080"], capture_output=True, text=True).stdout.strip() == "listening":
            break
        time.sleep(0.2)
    start(PY, str(HERE / "blue_watch.py"), str(W / "blue-timeline.csv"), str(W / "app"))
    for _ in range(100):  # wait until the app answers and the detector has taken its first look
        if (W / "blue-timeline.csv.ready").exists():
            break
        time.sleep(0.2)
    time.sleep(1)
    rc, _ = A("wrap", "--host", "127.0.0.99", "--", PY, "-c", "print(1)")
    expect("a command aimed at an out-of-scope address is refused before it runs", rc != 0)

    step("alpha: look at the app, then make three recorded changes")
    cfg = "http://127.0.0.11:18080/config"
    A("wrap", "--host", "127.0.0.11", "--class", "network-logon", "--text", "read the app config", "--", PY, str(HERE / "helpers.py"), "get", cfg); time.sleep(1)
    _, o = A("change", "add", "--kind", "config", "--host", "127.0.0.11", "--object", "app.ini", "--change", "limit=9999",
             "--capture", H("get", cfg), "--rollback-cmd", H("get", cfg, "limit=100"), show=False)
    c1 = ident("C", o)
    A("wrap", "--host", "127.0.0.11", "--class", "write-to-disk", "--text", "change the app config limit to 9999", "--", PY, str(HERE / "helpers.py"), "get", cfg, "limit=9999"); time.sleep(1.5)
    users = str(W / "app" / "users.txt")
    _, o = A("change", "add", "--kind", "account", "--host", "127.0.0.11", "--object", "app user drillsvc", "--change", "add user", "--created",
             "--capture", H("count", users, "drillsvc"), "--rollback-cmd", H("drop", users, "drillsvc"), show=False)
    c2 = ident("C", o)
    _, o = A("wrap", "--host", "127.0.0.11", "--class", "user-add", "--text", "add user drillsvc to the app", "--", PY, str(HERE / "helpers.py"), "get", "http://127.0.0.11:18080/users", "drillsvc")
    user_act = ident("A", o); time.sleep(1.5)
    pidfile = W / "listener.pid"
    _, o = A("change", "add", "--kind", "infra", "--host", "127.0.0.12", "--object", "listener 127.0.0.12:18081", "--change", "serve ./files on 18081",
             "--created", "--autonomous", "--capture", H("probe", "127.0.0.12", "18081"), "--rollback-cmd", H("stop", pidfile), show=False)
    c3 = ident("C", o)
    A("log", "--host", "127.0.0.12", "--class", "process-creation", "start a file listener on 127.0.0.12:18081")
    lp = start(PY, "-m", "http.server", "18081", "--bind", "127.0.0.12", cwd=str(W / "files"))
    pidfile.write_text(str(lp.pid)); time.sleep(3)
    hosts = W / "hosts"; hosts.write_text("")
    _, o = B("change", "add", "--kind", "file", "--host", "127.0.0.13", "--object", "hosts-line", "--change", "add line", "--created",
             "--capture", H("count", hosts, "files.example"), "--rollback-cmd", H("drop", hosts, "files.example"), show=False)
    c5 = ident("C", o)
    hosts.write_text("10.0.0.5 files.example\n")
    B("log", "--host", "127.0.0.13", "--class", "write-to-disk", "add a line to the hosts file on 127.0.0.13")
    print("(bravo changed a host that blue does not watch)")

    step("a failing path: two attempts on the same wrong assumption")
    for t in ("GET /admin returned 403", "GET /admin returned 403 again"):
        _, o = A("log", "--host", "127.0.0.11", "--layer", "authorization", "--result", "fail", "--assumption", "admin cookie works on /admin", t)
    expect("the repeated-assumption warning fired on the second failure", "failed 2 times" in o)

    step("blue-side analyst escalates (staged): freeze, SITREP, recommendation, decision, resume")
    time.sleep(1)
    B("detect", "L3", "--host", "127.0.0.11", "--source", "blue-lead", "--action", user_act, "--evidence", "staged: incident opened after the new-account alert")
    _, o = A("freeze", "--reason", "blue escalated to L3 (staged)")
    expect("freeze listed the listener that keeps running with no operator", c3 in o)
    rc, _ = A("log", "--host", "127.0.0.11", "try to keep going")
    expect("an action against a target is refused while frozen", rc != 0)
    _, o = A("log", "--list", show=False)
    A("sitrep", "--status", "frozen at L3", "--observed", "an incident was opened on 127.0.0.11", "--assessed", "our new-account change was seen",
      "--ask", "Control Team to decide", "--risk", "client responders may act on our assets", "--based-on", ident("A", o))
    A("recommend", "limited-purple", "--why", "alert was caused by us; let blue finish triage")
    _, o = C("decide", "limited-purple", "--by", "casey", "--why", "tell the analyst this is the engagement, keep scope as is", "--recommended-by", "alpha")
    rc, _ = C("resume", "--approved-by", "casey", "--decision", ident("D", o))
    expect("the Control Team decided and resumed the engagement", rc == 0)

    step("teardown: alpha rolls back; one rollback is left incomplete on purpose")
    A("teardown")
    A("change", "rollback", c3, "--run", "--verify")
    A("change", "rollback", c2, "--how", "removed user line", "--run", "--verify")
    rc, _ = A("change", "rollback", c1, "--how", "restored limit but left the 'mode' line edited", "--verify")
    expect("a read-back by the same operator who rolled back is refused", rc != 0)
    (W / "app" / "app.ini").write_text("mode=changed\nlimit=100\n")
    rc, _ = B("change", "verify", c1)
    expect("the second operator's read-back caught the incomplete rollback (mismatch)", rc == 2)
    (W / "app" / "app.ini").write_text("mode=standard\nlimit=100\n")
    rc, _ = B("change", "verify", c1)
    expect("after the fix the read-back matches", rc == 0)
    for c in (c2, c3):
        rc, _ = B("change", "verify", c)
        expect(f"{c} read-back matches", rc == 0)
    B("change", "rollback", c5, "--run", "--verify")
    rc, _ = A("change", "verify", c5)
    expect("the hosts-file change was rolled back and verified", rc == 0)

    step("closeout gate")
    A("close", "--check")
    out = W / "out"
    rc, o = A("close", "--out", str(out))
    expect("closeout came back CLEAN", rc == 0 and "CLEAN." in o)
    _, o = A("review", str(W / "blue-timeline.csv"), "--window", "1", show=False)
    (W / "review.txt").write_text(o)
    print(o.rstrip())
    A("navigator", str(W / "blue-timeline.csv"), "--out", str(out / "navigator.json"), show=False)
    rc, _ = A("verify-pack", str(out / "closeout-pack.zip"))
    expect("the closeout pack verifies", rc == 0)
    m = re.search(r"(\d+) of (\d+) actions were seen", o)
    print(f"\nreview: {m.group(0) if m else 'see review.txt'}")
    bad = [n for n, ok in checks if not ok]
    print(f"\nDRILL RESULT: {len(checks) - len(bad)} of {len(checks)} checks behaved as expected" + (f"; unexpected: {bad}" if bad else ""))
    print(f"drill folder: {W}")
    return 1 if bad else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        for p in procs:
            try:
                p.terminate()
            except OSError:
                pass
    sys.exit(code)
