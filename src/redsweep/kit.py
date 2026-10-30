"""The test kit: run it on your own machine before you trust Redsweep with a real engagement."""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from .store import Store
from .ops import Engagement, OpsError
from .closeout import check, blockers
from . import seal as seal_mod, mcp, importers

STEPS = []


def step(name):
    def deco(fn):
        STEPS.append((name, fn))
        return fn
    return deco


def _eng(td, op="alice", scope=None, cfg=None):
    st = Store(Path(td) / ".lt")
    st.init("KIT", "kit", op)
    sc = {"engagement": "KIT", "window": {"start": "2020-01-01T00:00:00Z", "end": "2099-01-01T00:00:00Z"},
          "in_scope": {"hosts": ["*.lab.example", "127.0.0.1"]}, "out_of_scope": ["bad.lab.example"], "forbidden_actions": ["denial-of-service"],
          "roles": {"control_team": ["pat"]}, "tripwires": ["external_party"]}
    sc.update(scope or {})
    st.scope_path.write_text(json.dumps(sc))
    if cfg:
        c = json.loads(st.config_path.read_text()); c.update(cfg); st.config_path.write_text(json.dumps(c))
    return Engagement(st, op)


def _expect_refused(fn, *a, **k):
    try:
        fn(*a, **k)
    except OpsError:
        return True
    return False


@step("journal chain detects an edited byte")
def _(td):
    e = _eng(td)
    e.note("one"); e.note("two")
    p = e.store.files()[0]
    p.write_text(p.read_text().replace("two", "tw0"))
    ok = [r[1] for r in e.store.verify()]
    return ok == [False]


@step("scope guard refuses out-of-scope and unlisted targets")
def _(td):
    e = _eng(td)
    return (_expect_refused(e.log_action, "x", host="bad.lab.example") and _expect_refused(e.log_action, "x", host="other.example")
            and e.log_action("x", host="a.lab.example")[0]["id"])


@step("a change cannot be recorded without its original value")
def _(td):
    e = _eng(td)
    return _expect_refused(e.add_change, "config", "a.lab.example", "obj", "chg")


def _cat(path):  # works the same in sh and cmd.exe
    return f'"{sys.executable}" -c "import sys;sys.stdout.write(open(sys.argv[1]).read())" "{path}"'


def _put(path, text):
    return f'"{sys.executable}" -c "import sys;open(sys.argv[1],\'w\').write(sys.argv[2]+chr(10))" "{path}" "{text}"'


@step("rollback is not finished until a read-back matches")
def _(td):
    f = Path(td) / "f.txt"; f.write_text("v1\n")
    e = _eng(td)
    c = e.add_change("file", "127.0.0.1", str(f), "edit", capture=_cat(f), rollback_cmd=_put(f, "v1"))
    f.write_text("v2\n")
    if not blockers(check(e)):
        return False
    e.rollback(c["id"], run=True)
    still = blockers(check(e))
    r = e.verify(c["id"])
    return bool(still) and r["result"] == "match" and not blockers(check(e))


@step("an incomplete rollback is caught as a mismatch")
def _(td):
    f = Path(td) / "g.txt"; f.write_text("a\n")
    e = _eng(td)
    c = e.add_change("file", "127.0.0.1", str(f), "edit", capture=_cat(f))
    f.write_text("a\nleftover\n")
    e.rollback(c["id"], how="removed my line")
    return e.verify(c["id"])["result"] == "mismatch" and bool(blockers(check(e)))


@step("secrets are stored as a fingerprint, never as text")
def _(td):
    e = _eng(td)
    e.add_change("config", "127.0.0.1", "k", "c", original="aws_secret_access_key = AKIAABCDEFGHIJKLMNOP")
    j = e.store.files()[0].read_text()
    return "AKIAABCDEFGHIJKLMNOP" not in j and "protected sha256" in j


@step("only a Control Team member can decide or resume")
def _(td):
    e = _eng(td)
    e.freeze("test")
    return (_expect_refused(e.decide, "go-dark", "alice", "why") and _expect_refused(e.resume, "alice") and e.decide("go-dark", "pat", "why")
            and e.resume("pat"))


@step("a frozen engagement refuses operator activity on a target")
def _(td):
    e = _eng(td)
    e.freeze("test")
    return _expect_refused(e.log_action, "x", host="a.lab.example") and _expect_refused(e.add_change, "file", "a.lab.example", "o", "c", created=True)


@step("credential containment waits for steps and the token window")
def _(td):
    e = _eng(td)
    k = e.add_cred("gcp-access-token", "svc@proj", material="x")
    st = e.state()
    if st.cred_status(st.creds[k["id"]])[0] != "not_started":
        return False
    for i in range(1, len(st.creds[k["id"]]["steps"]) + 1):
        e.cred_step(k["id"], i)
    st = e.state()
    return st.cred_status(st.creds[k["id"]])[0] == "in_progress"  # window of 3600s is still open


@step("seal and pack verify, and a tampered pack fails")
def _(td):
    e = _eng(td)
    e.note("hello")
    seal = seal_mod.make_seal(e.store, {"closeout.md": "x"})
    pk = Path(td) / "p.zip"
    seal_mod.build_pack(e.store, str(pk), {"closeout.md": "x"}, seal)
    ok1, _ = seal_mod.verify_pack(str(pk))
    bad = Path(td) / "bad.zip"
    with zipfile.ZipFile(pk) as zi, zipfile.ZipFile(bad, "w") as zo:
        for n in zi.namelist():
            data = zi.read(n)
            if n.endswith(".jsonl"):
                data = data.replace(b"hello", b"jello")
            zo.writestr(n, data)
    ok2, _ = seal_mod.verify_pack(str(bad))
    return ok1 and not ok2


@step("MCP server lists tools and refuses out-of-scope work")
def _(td):
    e = _eng(td)
    e.allow_exec = False
    r = mcp.handle(e, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    r2 = mcp.handle(e, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "redsweep_log_action", "arguments": {"text": "x", "host": "bad.lab.example"}}})
    return "redsweep_change_add" in names and r2["result"].get("isError") is True and "waive" not in " ".join(names)


@step("importing the same log twice adds nothing the second time")
def _(td):
    e = _eng(td)
    f = Path(td) / "b.log"
    f.write_text("10/03 09:12:44 UTC [input] <alice> pwd\n")
    a1 = importers.do_import(e, "cobalt-strike", str(f), 2026, "127.0.0.1")
    a2 = importers.do_import(e, "cobalt-strike", str(f), 2026, "127.0.0.1")
    return a1 == (1, 0) and a2 == (0, 1)


POSIX_ONLY = set()  # every step now runs on Windows too; only the live lab needs a POSIX shell


def selftest(keep=False):
    td = tempfile.mkdtemp(prefix="redsweep-kit-")
    bad = 0
    print(f"Redsweep test kit (working in {td})\n")
    for i, (name, fn) in enumerate(STEPS, 1):
        sub = Path(td) / f"s{i}"; sub.mkdir()
        if os.name == "nt" and name in POSIX_ONLY:
            print(f"  [SKIP] {i:2}. {name}  (needs a POSIX shell)")
            continue
        try:
            ok = bool(fn(sub))
        except Exception as e:  # a crash is a failure, and we say which
            ok, name = False, f"{name}  (crashed: {type(e).__name__}: {e})"
        print(f"  [{'PASS' if ok else 'FAIL'}] {i:2}. {name}")
        bad += not ok
    if os.name == "nt":
        print(f"  [SKIP] {len(STEPS) + 1:2}. live lab  (needs curl and a POSIX shell)")
        code, buf = 0, io.StringIO()
    else:
        from .lab import run_lab
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = run_lab(Path(td) / "lab")
        print(f"  [{'PASS' if code == 0 else 'FAIL'}] {len(STEPS) + 1:2}. live lab: real commands, changes and rollbacks on this machine")
    bad += code != 0
    if code != 0:
        print(buf.getvalue()[-1500:])
    print(f"\n{'All checks passed.' if not bad else str(bad) + ' check(s) FAILED.'}")
    if not keep:
        shutil.rmtree(td, ignore_errors=True)
    return 1 if bad else 0
