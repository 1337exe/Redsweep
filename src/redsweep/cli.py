"""Command line. Exit codes: 0 fine, 1 refused or error, 2 closeout has blockers, 3 a journal or pack fails verification."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, importers, pricing, review as review_mod, seal as seal_mod
from .closeout import blockers, check, report_data, to_html, to_markdown
from .control import build_sitrep, render_sitrep, autonomous_list
from .exporters import export
from .model import (CHANGE_KINDS, DECISION_OPTIONS, ERROR_LAYERS, FAMILIES, LADDER, LADDER_HELP, LEVELS, STOP_CONDITIONS)
from .ops import Engagement, OpsError
from .scope import ScopeError
from .state import RefError
from .store import Store, StoreError
from .util import iso, now, sha256_text, short


def _common():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--home", help="engagement folder (default ./.redsweep or $REDSWEEP_HOME)")
    p.add_argument("--operator", help="who you are (default $REDSWEEP_OPERATOR or your user name)")
    return p


def build_parser():
    C = _common()
    ap = argparse.ArgumentParser(prog="redsweep", description="Sweep the engagement clean, and prove it. Change ledger, rollback verifier and control-team kit for red team engagements.")
    ap.add_argument("--version", action="version", version=f"redsweep {__version__}")
    sp = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def add(name, help_, **kw):
        return sp.add_parser(name, help=help_, parents=[C], **kw)

    p = add("init", "start an engagement folder")
    p.add_argument("--name", required=True); p.add_argument("--client", default=""); p.add_argument("--force", action="store_true")
    add("status", "where the engagement stands, right now")

    p = add("scope", "check a target against the rules of engagement")
    p.add_argument("action", choices=["check"]); p.add_argument("target"); p.add_argument("--class", dest="cls")

    p = add("log", "write to the operator log (or list it with --list)")
    p.add_argument("text", nargs="?"); p.add_argument("--list", action="store_true"); p.add_argument("-n", type=int, default=20)
    p.add_argument("--host"); p.add_argument("--layer", default="n/a", choices=ERROR_LAYERS)
    p.add_argument("--result", default="ok", choices=["ok", "fail", "partial", "planned"])
    p.add_argument("--assumption"); p.add_argument("--new-info", action="store_true", help="this attempt taught you something new")
    p.add_argument("--class", dest="cls"); p.add_argument("--at", help="time in UTC (default now)")
    p.add_argument("--scope-override"); p.add_argument("--tripwire"); p.add_argument("--decision")

    p = add("wrap", "run a command and log it (command, exit code, output hash)")
    p.add_argument("--host"); p.add_argument("--class", dest="cls"); p.add_argument("--assumption"); p.add_argument("--scope-override")
    p.add_argument("--layer", default="n/a", choices=ERROR_LAYERS); p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--text", help="a readable description for the log (the full command is still stored)")
    p.add_argument("argv", nargs=argparse.REMAINDER)

    p = add("act", "before you act: price it and answer the three questions")
    p.add_argument("cls"); p.add_argument("--payoff", required=True, help="what concrete change does this buy?")
    p.add_argument("--reversible", required=True, help="what changes, can you restore it, can you prove it?")
    p.add_argument("--host"); p.add_argument("--scope-override")

    p = add("price", "what does an action leave behind?")
    p.add_argument("cls", nargs="?"); p.add_argument("--list", action="store_true")

    # change ledger
    p = add("change", "the change ledger")
    cs = p.add_subparsers(dest="sub", required=True)
    q = cs.add_parser("add", parents=[C], help="record a change BEFORE you make it")
    q.add_argument("--kind", required=True, choices=sorted(CHANGE_KINDS)); q.add_argument("--host"); q.add_argument("--object", required=True)
    q.add_argument("--change", required=True, help="what you are changing it to")
    q.add_argument("--capture", help="a read-only command that prints the current state (best: Redsweep can run it again later)")
    q.add_argument("--original"); q.add_argument("--original-file"); q.add_argument("--created", action="store_true", help="the object did not exist before")
    q.add_argument("--ignore", action="append", help="regex of lines to ignore when comparing (timestamps, etags)")
    q.add_argument("--rollback-plan", default=""); q.add_argument("--rollback-cmd")
    q.add_argument("--autonomous", dest="autonomous", action="store_true", default=None); q.add_argument("--no-autonomous", dest="autonomous", action="store_false")
    q.add_argument("--etag"); q.add_argument("--secret", action="store_true", help="store only a fingerprint of the original value")
    q.add_argument("--scope-override"); q.add_argument("--tripwire"); q.add_argument("--decision"); q.add_argument("--tag", action="append")
    q.add_argument("--at")
    cs.add_parser("list", parents=[C], help="all changes and their status").add_argument("--open", action="store_true")
    q = cs.add_parser("show", parents=[C]); q.add_argument("ref")
    q = cs.add_parser("rollback", parents=[C], help="record a rollback (or run the stored rollback command)")
    q.add_argument("ref"); q.add_argument("--how"); q.add_argument("--run", action="store_true"); q.add_argument("--durable", help="control that survives the rollback")
    q.add_argument("--verify", action="store_true", help="read it back straight away")
    q = cs.add_parser("verify", parents=[C], help="independent read-back after the rollback")
    q.add_argument("ref"); q.add_argument("--readback-value"); q.add_argument("--readback-file")
    q.add_argument("--attest", action="store_true"); q.add_argument("--note"); q.add_argument("--force", action="store_true")
    q = cs.add_parser("waive", parents=[C], help="accept a residual risk, in writing")
    q.add_argument("ref"); q.add_argument("--reason", required=True); q.add_argument("--by", required=True)

    # credentials
    p = add("cred", "credential containment")
    cc = p.add_subparsers(dest="sub", required=True)
    q = cc.add_parser("add", parents=[C]); q.add_argument("--family", required=True, choices=sorted(FAMILIES)); q.add_argument("--principal", required=True)
    q.add_argument("--label", default=""); q.add_argument("--material-file"); q.add_argument("--location", default="")
    q.add_argument("--host"); q.add_argument("--issued-latest", help="latest possible issue time (UTC); default now")
    q.add_argument("--lifetime", type=int, help="seconds the token lives (default from family)"); q.add_argument("--scope-override")
    cc.add_parser("list", parents=[C])
    q = cc.add_parser("show", parents=[C]); q.add_argument("ref")
    q = cc.add_parser("step", parents=[C], help="mark a containment step done"); q.add_argument("ref"); q.add_argument("step", type=int); q.add_argument("--note", default="")
    q = cc.add_parser("accept-window", parents=[C], help="accept that already-issued tokens stay valid"); q.add_argument("ref"); q.add_argument("--reason", required=True); q.add_argument("--by", required=True)

    # evidence
    p = add("evidence", "evidence custody")
    ee = p.add_subparsers(dest="sub", required=True)
    q = ee.add_parser("add", parents=[C]); q.add_argument("path"); q.add_argument("--label", required=True); q.add_argument("--ladder", default="metadata", choices=LADDER)
    q.add_argument("--host"); q.add_argument("--approved-by"); q.add_argument("--copy", action="store_true")
    ee.add_parser("list", parents=[C])
    q = ee.add_parser("handoff", parents=[C]); q.add_argument("ref"); q.add_argument("--to", required=True); q.add_argument("--purpose", required=True)
    q = ee.add_parser("destroy", parents=[C]); q.add_argument("ref"); q.add_argument("--method", required=True); q.add_argument("--witness", required=True); q.add_argument("--delete", action="store_true")

    p = add("canary", "plant and prove a synthetic record")
    cn = p.add_subparsers(dest="sub", required=True)
    q = cn.add_parser("make", parents=[C]); q.add_argument("--label", required=True)
    q = cn.add_parser("check", parents=[C], help="prove you read the canary by digest, without keeping the content")
    q.add_argument("--file", required=True); q.add_argument("--expect", required=True, help="digest the Control Team gave you"); q.add_argument("--label", default="")

    p = add("detect", "record that the blue team noticed something")
    p.add_argument("level"); p.add_argument("--host"); p.add_argument("--source", default=""); p.add_argument("--evidence", default=""); p.add_argument("--at"); p.add_argument("--action")
    add("levels", "print the detection scale")

    p = add("freeze", "stop all operator activity and list what is still running")
    p.add_argument("--reason", required=True)
    p = add("stop", "a stop condition was hit")
    p.add_argument("--condition", required=True, choices=sorted(STOP_CONDITIONS)); p.add_argument("--reason", required=True)
    p = add("resume", "Control Team: lift the freeze")
    p.add_argument("--approved-by", required=True); p.add_argument("--decision")

    p = add("recommend", "red team: recommend an option to the Control Team")
    p.add_argument("option", choices=DECISION_OPTIONS); p.add_argument("--why", required=True); p.add_argument("--also", action="append", choices=DECISION_OPTIONS)
    p = add("decide", "Control Team: record a decision")
    p.add_argument("option", choices=DECISION_OPTIONS); p.add_argument("--by", required=True); p.add_argument("--why", required=True)
    p.add_argument("--tag", action="append"); p.add_argument("--recommended-by")

    p = add("sitrep", "write a SITREP from the operator log (or show one with --show N)")
    p.add_argument("--status"); p.add_argument("--observed"); p.add_argument("--assessed", default=""); p.add_argument("--ask"); p.add_argument("--risk", default="")
    p.add_argument("--based-on", help="comma list of log ids, e.g. A-1a2b3,A-4c5d6"); p.add_argument("--not-yet", default=""); p.add_argument("--exposed", action="append")
    p.add_argument("--show", type=int)

    add("teardown", "the ordered cleanup list, built from the ledger")
    p = add("close", "closeout gate: refuse to close until everything is undone and proved")
    p.add_argument("--check", action="store_true", help="only print the check; write nothing"); p.add_argument("--out"); p.add_argument("--no-pack", action="store_true"); p.add_argument("--key-file"); p.add_argument("--gpg-key", help="sign the seal with this gpg key (needs gpg)")

    p = add("review", "purple review: join the operator log with the blue timeline")
    p.add_argument("blue"); p.add_argument("--window", type=int, default=30, help="minutes after an action in which an alert counts"); p.add_argument("--json", action="store_true")
    p = add("import", "bring in a log from another tool")
    p.add_argument("fmt", choices=sorted(importers.FORMATS)); p.add_argument("file"); p.add_argument("--year", type=int); p.add_argument("--host"); p.add_argument("--dry-run", action="store_true")
    p.add_argument("--map", action="append", metavar="NAME=COLUMN", help="for csv/jsonl: use COLUMN as NAME (time, text, host, result, class, operator); repeat for each")
    p = add("export", "write the log out for another tool")
    p.add_argument("fmt", choices=["ghostwriter", "json", "markdown"]); p.add_argument("--out")

    p = add("navigator", "write an ATT&CK Navigator layer coloured by what blue saw"); p.add_argument("blue", nargs="?"); p.add_argument("--out", default="redsweep-layer.json"); p.add_argument("--window", type=int, default=30)
    p = add("handoff", "write the list of things the client must do or know"); p.add_argument("--out")
    add("verify", "check every journal's hash chain")
    p = add("seal", "fix the journal heads and reports in a seal"); p.add_argument("--key-file"); p.add_argument("--gpg-key", help="sign the seal with this gpg key (needs gpg)")
    p = add("verify-pack", "check a closeout pack zip"); p.add_argument("pack"); p.add_argument("--key-file")
    add("mcp", "run the MCP server on stdio")
    add("doctor", "check this machine")
    p = add("demo", "build a made-up engagement to look at"); p.add_argument("dir", nargs="?", default="redsweep-demo"); p.add_argument("--finish", action="store_true", help="also do the cleanup, so closeout passes")
    p = add("lab", "run a real local exercise: real commands, real changes, real rollbacks"); p.add_argument("dir", nargs="?", default="redsweep-lab"); p.add_argument("--keep", action="store_true")
    p = add("selftest", "run the full test kit on this machine"); p.add_argument("--keep", action="store_true")
    return ap


def _eng(a, exec_ok=True):
    return Engagement(Store(a.home), a.operator, allow_exec=exec_ok)


def _say(*x):
    print(*x)


def cmd_init(a):
    s = Store(a.home)
    s.init(a.name, a.client, a.operator or "", a.force)
    _say(f"engagement '{a.name}' started in {s.home}")
    _say(f"  edit {s.scope_path} (targets, forbidden actions, Control Team names) before anyone starts work")
    return 0


def cmd_status(a):
    e = _eng(a)
    st = e.state()
    items = check(e)
    b = blockers(items)
    _say(f"{st.meta.get('name', '?')}  ({st.meta.get('client') or 'no client'})   {st.event_count} events, {len(set(c['op'] for c in st.changes.values()) | {x['op'] for x in st.actions})} operator(s)")
    _say(f"state       : {'FROZEN: ' + st.freeze_info['reason'] if st.frozen else 'active'}")
    _say(f"log         : {len(st.actions)} actions, {sum(1 for x in st.actions if x.get('result') == 'fail')} failures recorded")
    ch = st.changes.values()
    _say(f"changes     : {len(st.changes)} total, {sum(1 for c in ch if c['status'] == 'verified')} verified, {len(st.active_changes())} open")
    _say(f"credentials : {len(st.creds)} total, {sum(1 for k in st.creds.values() if st.cred_status(k)[0] != 'confirmed')} not contained")
    _say(f"evidence    : {len(st.held_evidence())} held")
    _say(f"closeout    : {'CLEAN' if not b else str(len(b)) + ' blocker(s)'}")
    for m in st.warnings[-3:]:
        _say("  warning:", m)
    if st.problems:
        _say("  JOURNAL PROBLEMS:", *st.problems)
        return 3
    return 0


def cmd_scope(a):
    e = _eng(a)
    if not e.scope:
        _say("no scope.json")
        return 1
    v, why = e.scope.check(a.target)
    _say(f"{a.target}: {v.upper()}  ({why})")
    ok, w = e.scope.check_window()
    if not ok:
        _say("  window:", w)
    if a.cls:
        av, aw = e.scope.check_action(a.cls)
        _say(f"  action {a.cls}: {av}" + (f" ({aw})" if aw else ""))
        if av == "forbidden":
            return 1
    return 0 if v == "in" and ok else 1


def cmd_log(a):
    e = _eng(a)
    if a.list:
        for x in e.state().actions[-a.n:]:
            _say(f"{x['id']}  {x['t']}  {x.get('result', 'ok'):7} {x.get('host') or '-':18} {short(x['text'], 70)}")
        return 0
    if not a.text:
        _say("nothing to log: give TEXT, or use --list")
        return 1
    ev, warn = e.log_action(a.text, host=a.host, layer=a.layer, result=a.result, assumption=a.assumption, new_info=a.new_info, cls=a.cls,
                            override=a.scope_override, tripwire=a.tripwire, decision=a.decision, at=a.at)
    _say(f"logged {ev['id']}")
    if warn:
        _say("WARNING:", warn)
    return 0


def cmd_wrap(a):
    e = _eng(a)
    argv = a.argv[1:] if a.argv and a.argv[0] == "--" else a.argv
    if not argv:
        _say("usage: redsweep wrap [options] -- COMMAND ARGS")
        return 1
    e._active(e.state())
    e._guard(a.host, a.cls, a.scope_override)
    t0 = time.time()
    started = iso(now())  # the action happened when it started, not when it finished
    try:
        p = subprocess.run(argv, capture_output=True, timeout=a.timeout)
    except FileNotFoundError:
        _say(f"command not found: {argv[0]}")
        return 127
    except subprocess.TimeoutExpired:
        e.log_action(a.text or " ".join(argv), host=a.host, result="fail", layer="tooling", cls=a.cls, cmd=" ".join(argv), exit_code=-1, at=started)
        _say("timed out; logged as a failure")
        return 124
    sys.stdout.buffer.write(p.stdout); sys.stderr.buffer.write(p.stderr)
    ev, warn = e.log_action(a.text or " ".join(argv), host=a.host, result="ok" if p.returncode == 0 else "fail", layer=a.layer, cls=a.cls,
                            assumption=a.assumption, cmd=" ".join(argv), exit_code=p.returncode, out_sha=sha256_text((p.stdout + p.stderr).decode(errors="replace")),
                            override=a.scope_override, at=started)
    print(f"[redsweep] logged {ev['id']} (exit {p.returncode}, {time.time() - t0:.1f}s)", file=sys.stderr)
    if warn:
        print("[redsweep] WARNING:", warn, file=sys.stderr)
    return p.returncode


def cmd_act(a):
    e = _eng(a)
    _say(pricing.explain(a.cls))
    ev, _ = e.log_action(f"planned: {a.cls}", host=a.host, result="planned", cls=a.cls, override=a.scope_override,
                         intent={"payoff": a.payoff, "reversible": a.reversible})
    _say(f"\nplanned and logged as {ev['id']}. If the payoff is unclear, or you cannot restore and prove it, do not do it.")
    return 0


def cmd_price(a):
    if a.list or not a.cls:
        for k in sorted(pricing.PRICES):
            _say(f"{k:30} {pricing.PRICES[k][0]}")
        return 0
    _say(pricing.explain(a.cls))
    return 0 if a.cls in pricing.PRICES else 1


def cmd_change(a):
    e = _eng(a)
    if a.sub == "add":
        ev = e.add_change(a.kind, a.host, a.object, a.change, original=a.original, original_file=a.original_file, capture=a.capture,
                          ignore=a.ignore, created=a.created, rollback_plan=a.rollback_plan, rollback_cmd=a.rollback_cmd, autonomous=a.autonomous,
                          etag=a.etag, secret=a.secret, override=a.scope_override, tripwire=a.tripwire, decision=a.decision, tags=a.tag, at=a.at)
        _say(f"recorded {ev['id']}. Original value is saved. Make the change now; roll it back and read it back before closeout.")
        return 0
    st = e.state()
    if a.sub == "list":
        for c in st.changes.values():
            if a.open and c["status"] in ("verified", "waived"):
                continue
            _say(f"{c['id']}  {c['status']:11} {c['kind']:11} {c.get('host') or '-':16} {short(c['object'], 60)}")
        return 0
    if a.sub == "show":
        cid, c = st.find(st.changes, a.ref, "change")
        for k in ("id", "t", "op", "kind", "host", "object", "change", "status", "original_display", "capture", "rollback_plan", "rollback_cmd", "durable"):
            _say(f"{k:16}: {c.get(k)}")
        _say("history         :", " -> ".join(f"{h[0]}({h[2]})" for h in c["history"]))
        if c["verify"]:
            _say("read-back       :", c["verify"])
        return 0
    if a.sub == "rollback":
        ev, res = e.rollback(a.ref, how=a.how, run=a.run, durable=a.durable, verify=a.verify)
        _say("rollback recorded." + (" Now read it back: `redsweep change verify " + a.ref + "`" if not a.verify else ""))
        if res:
            _say(f"read-back: {res['result'].upper()} ({res['strength']})")
            return 0 if res["result"] == "match" else 2
        return 0
    if a.sub == "verify":
        r = e.verify(a.ref, readback_value=a.readback_value, readback_file=a.readback_file, note=a.note, attest=a.attest, force=a.force)
        _say(f"{r['id']}: read-back {r['result'].upper()} ({r['strength']})")
        if r["result"] != "match":
            _say("  the current state differs from the value recorded before the change. Look again; do not close.")
        return 0 if r["result"] == "match" else 2
    if a.sub == "waive":
        e.waive(a.ref, a.reason, a.by)
        _say("waiver recorded. It will appear in the closeout report.")
        return 0


def cmd_cred(a):
    e = _eng(a)
    if a.sub == "add":
        ev = e.add_cred(a.family, a.principal, a.label, material_file=a.material_file, location=a.location, host=a.host,
                        issued_latest=a.issued_latest, lifetime=a.lifetime, override=a.scope_override)
        st = e.state(); c = st.creds[ev["id"]]
        _say(f"recorded {ev['id']} (only a hash of the material is kept)")
        if c.get("window_end"):
            _say(f"tokens issued up to now stay valid until {c['window_end']} UTC")
        _say("containment steps:")
        for i, s in enumerate(c["steps"], 1):
            _say(f"  {i}. {s}")
        return 0
    st = e.state()
    if a.sub == "list":
        for k in st.creds.values():
            s, w, we = st.cred_status(k)
            _say(f"{k['id']}  {s:11} {k['family']:16} {k['principal']:24} steps {len(k['steps_done'])}/{len(k['steps'])}" + (f"  window until {iso(we)}" if w else ""))
        return 0
    if a.sub == "show":
        kid, k = st.find(st.creds, a.ref, "credential")
        s, w, we = st.cred_status(k)
        _say(f"{kid} {k['family']} {k['principal']}  status {s}")
        for i, step in enumerate(k["steps"], 1):
            _say(f"  [{'x' if i in k['steps_done'] else ' '}] {i}. {step}")
        return 0
    if a.sub == "step":
        e.cred_step(a.ref, a.step, a.note)
        _say("step recorded")
        return 0
    if a.sub == "accept-window":
        e.cred_window(a.ref, a.reason, a.by)
        _say("recorded; it will appear in the closeout report")
        return 0


def cmd_evidence(a):
    e = _eng(a)
    if a.sub == "add":
        ev = e.add_evidence(a.path, a.label, a.ladder, a.host, a.approved_by, a.copy)
        _say(f"recorded {ev['id']}  sha256 {ev['data']['sha256'][:16]}…  ({a.ladder}: {LADDER_HELP[a.ladder]})")
        return 0
    if a.sub == "list":
        for x in e.state().evidence.values():
            st_ = "destroyed" if x["destroyed"] else ("handed over" if x["handoffs"] else "held")
            _say(f"{x['id']}  {st_:11} {x['ladder']:11} {x['label']}  {x['sha256'][:12]}")
        return 0
    if a.sub == "handoff":
        e.handoff(a.ref, a.to, a.purpose); _say("handoff recorded"); return 0
    if a.sub == "destroy":
        e.destroy(a.ref, a.method, a.witness, a.delete); _say("destruction record written"); return 0


def cmd_canary(a):
    e = _eng(a)
    if a.sub == "make":
        rec, digest = e.canary_make(a.label)
        _say(json.dumps(rec, indent=2))
        _say(f"\nGive this record to the Control Team to plant. Digest of the record: {digest}")
        return 0
    data = Path(a.file).read_text(errors="replace")
    ok, ev = e.canary_check(data, a.expect, a.label)
    _say("canary read PROVEN (digest matches)" if ok else "canary digest does NOT match. You did not read the planted record.")
    return 0 if ok else 2


def cmd_detect(a):
    e = _eng(a)
    ev = e.detect(a.level, a.host, a.evidence, a.source, a.at, a.action)
    _say(f"recorded {ev['id']}: {a.level} {LEVELS.get(a.level, '')}")
    if a.level in ("L3", "L4", "L5"):
        _say("This is serious enough to freeze: `redsweep freeze --reason ...` and send a SITREP.")
    return 0


def cmd_levels(a):
    for k, v in _eng(a).cfg["levels"].items():
        _say(f"{k}  {v}")
    return 0


def cmd_freeze(a):
    e = _eng(a)
    e.freeze(a.reason)
    st = e.state()
    _say("FROZEN. No more operator activity until the Control Team resumes.")
    _say("Still running with no operator (the Control Team must decide what to do with these):")
    for l in autonomous_list(st) or ["nothing recorded in the ledger. Check that every implant, task and listener is in it."]:
        _say("  -", l)
    return 0


def cmd_stop(a):
    e = _eng(a)
    e.freeze(a.reason, a.condition)
    _say(f"STOPPED on '{a.condition}'. Resuming needs a Control Team decision.")
    return 0


def cmd_resume(a):
    _eng(a).resume(a.approved_by, a.decision)
    _say("resumed")
    return 0


def cmd_recommend(a):
    ev = _eng(a).recommend(a.option, a.why, a.also)
    _say(f"recommendation {ev['id']} recorded. The Control Team decides.")
    return 0


def cmd_decide(a):
    ev = _eng(a).decide(a.option, a.by, a.why, a.tag, recommended_by=a.recommended_by)
    _say(f"decision {ev['id']} recorded: {a.option} by {a.by}")
    return 0


def cmd_sitrep(a):
    e = _eng(a)
    if a.show:
        sr = [s for s in e.state().sitreps if s["n"] == a.show]
        if not sr:
            _say("no such SITREP"); return 1
        _say(render_sitrep(sr[0], sr[0]["t"], sr[0]["op"], sr[0]["id"]))
        return 0
    ev, d = build_sitrep(e, a.status or "see below", a.observed, a.assessed, a.ask, a.risk, [x for x in (a.based_on or "").split(",") if x], a.not_yet, a.exposed)
    _say(render_sitrep(d, ev["t"], ev["op"], ev["id"]))
    return 0


def cmd_teardown(a):
    for s in _eng(a).teardown_plan():
        _say(f"[{'x' if s['done'] else ' '}] {s['ref']:8} {s['text']}" + (f"   <- {s['why']}" if s["why"] else ""))
    _say("\nDomains: keep them registered until the client confirms the engagement is over.")
    return 0


def cmd_close(a):
    e = _eng(a)
    items = check(e)
    b = blockers(items)
    for i in items:
        if i["sev"] != "info" or a.check:
            _say(f"{i['sev'].upper():8} [{i['area']}] {i['ref']} {i['msg']}")
    if a.check:
        _say("\nclean" if not b else f"\n{len(b)} blocker(s)")
        return 2 if b else 0
    out = Path(a.out or e.store.home / "reports")
    out.mkdir(parents=True, exist_ok=True)
    r = report_data(e, items)
    from . import handoff
    reports = {"closeout.md": to_markdown(r), "closeout.html": to_html(r), "closeout.json": json.dumps(r, indent=2, default=str),
               "client-handoff.md": handoff.build(e.state())}
    for k, v in reports.items():
        (out / k).write_text(v)
    _say(f"report written to {out}/ (closeout.md, closeout.html, closeout.json, client-handoff.md)")
    if b:
        _say(f"\nNOT CLEAN: {len(b)} blocker(s). Fix them and run `redsweep close` again.")
        return 2
    seal = seal_mod.make_seal(e.store, reports, a.key_file)
    (out / "seal.json").write_text(seal_mod.dump(seal))
    extra = {}
    if a.gpg_key:
        asc = seal_mod.gpg_sign(str(out / "seal.json"), a.gpg_key)
        extra["seal.json.asc"] = Path(asc).read_bytes()
        _say(f"signed: {asc}")
    if not a.no_pack:
        pk, n = seal_mod.build_pack(e.store, str(out / "closeout-pack.zip"), reports, seal, extra)
        _say(f"pack: {pk} ({n} files)")
    _say("\nCLEAN. Everything changed was undone and proved undone." + ("" if "hmac_sha256" in seal or a.gpg_key else " (seal is unsigned; use --gpg-key or set REDSWEEP_KEY)"))
    return 0


def cmd_review(a):
    e = _eng(a)
    r = review_mod.review(e.state(), review_mod.load_blue(a.blue), a.window)
    _say(json.dumps(r, indent=2, default=str) if a.json else review_mod.to_markdown(r))
    return 0


def cmd_import(a):
    e = _eng(a)
    added, skipped = importers.do_import(e, a.fmt, a.file, a.year, a.host, a.dry_run, importers.parse_map(a.map))
    _say(f"{'would add' if a.dry_run else 'added'} {added} entries, skipped {skipped} already imported")
    return 0


def cmd_export(a):
    text = export(_eng(a).state(), a.fmt)
    if a.out:
        Path(a.out).write_text(text); _say(f"wrote {a.out}")
    else:
        _say(text)
    return 0


def cmd_navigator(a):
    from . import navigator
    e = _eng(a)
    blue = review_mod.load_blue(a.blue) if a.blue else []
    r = review_mod.review(e.state(), blue, a.window)
    lay = navigator.layer(r, e.state().meta.get("name", "engagement"))
    Path(a.out).write_text(navigator.dumps(lay))
    _say(f"wrote {a.out}: {len(lay['techniques'])} techniques. Open it at https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer > Upload).")
    return 0


def cmd_handoff(a):
    from . import handoff
    text = handoff.build(_eng(a).state())
    if a.out:
        Path(a.out).write_text(text); _say(f"wrote {a.out}")
    else:
        _say(text)
    return 0


def cmd_verify(a):
    s = Store(a.home)
    s.require()
    bad = False
    for name, ok, n, info in s.verify():
        _say(f"{'OK  ' if ok else 'FAIL'} {name}: {n} events" + ("" if ok else f"  {info}"))
        bad |= not ok
    return 3 if bad else 0


def cmd_seal(a):
    e = _eng(a)
    r = report_data(e)
    reports = {"closeout.md": to_markdown(r), "closeout.html": to_html(r), "closeout.json": json.dumps(r, indent=2, default=str)}
    seal = seal_mod.make_seal(e.store, reports, a.key_file)
    p = e.store.home / "seal.json"
    p.write_text(seal_mod.dump(seal))
    _say(f"wrote {p}" + ("" if "hmac_sha256" in seal or a.gpg_key else " (unsigned: set REDSWEEP_KEY, use --gpg-key, or sign the file yourself)"))
    if a.gpg_key:
        _say(f"signed: {seal_mod.gpg_sign(str(p), a.gpg_key)}")
    return 0


def cmd_verify_pack(a):
    ok, msgs = seal_mod.verify_pack(a.pack, a.key_file)
    bad_words = ("MISMATCH", "BAD signature", "No public key", "failed", "does not match", "unsafe", "missing", "broken", "not in manifest", "not a readable", "over the", "listed but")
    for m in msgs:
        _say(("FAIL " if any(w in m for w in bad_words) else "OK   ") + m)
    return 0 if ok else 3


def cmd_mcp(a):
    from . import mcp
    mcp.serve(Engagement(Store(a.home), a.operator, allow_exec=False))
    return 0


def cmd_doctor(a):
    import platform, shutil
    _say(f"redsweep {__version__}  python {platform.python_version()}  {platform.system()}")
    for t in ("git", "ssh-keygen", "gpg", "curl"):
        _say(f"  {t:11}: {'found' if shutil.which(t) else 'not found (optional)'}")
    s = Store(a.home)
    _say(f"  engagement  : {'found at ' + str(s.home) if s.exists() else 'none here'}")
    import os
    _say(f"  REDSWEEP_KEY : {'set' if os.environ.get('REDSWEEP_KEY') else 'not set (seals will be unsigned)'}")
    return 0


def cmd_demo(a):
    from .demo import build_demo
    return build_demo(a.dir, finish=a.finish)


def cmd_lab(a):
    from .lab import run_lab
    return run_lab(a.dir, a.keep)


def cmd_selftest(a):
    from .kit import selftest
    return selftest(a.keep)


def main(argv=None):
    a = build_parser().parse_args(argv)
    fn = globals()["cmd_" + a.cmd.replace("-", "_")]
    try:
        return fn(a)
    except (OpsError, StoreError, ScopeError, RefError, review_mod.ReviewError, importers.ImportError_, seal_mod.SealError, ValueError) as e:
        print(f"redsweep: {e}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
