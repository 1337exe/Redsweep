"""Everything an operator or an agent can do. The CLI and the MCP server both call this one layer, so they follow the same rules."""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path

from .model import (AUTONOMOUS_KINDS, CHANGE_KINDS, DECISION_OPTIONS, ERROR_LAYERS, FAMILIES, LADDER, STOP_CONDITIONS,
                    STRENGTH_RANK, TEARDOWN_ORDER)
from .redact import protect
from .scope import Scope, ScopeError
from .state import RefError, build
from .store import Store
from .util import iso, now, parse_time, sha256_file, sha256_text, canon, short
import datetime as dt
import json


class OpsError(Exception):
    pass


def normalize(text: str, ignore=None) -> str:
    rx = [re.compile(p) for p in (ignore or [])]
    lines = [l.rstrip() for l in (text or "").splitlines()]
    lines = [l for l in lines if not any(r.search(l) for r in rx)]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def run_shell(cmd: str, timeout: int = 30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise OpsError(f"command timed out after {timeout}s: {short(cmd, 60)}")
    return p.stdout + f"\n[exit={p.returncode}]", p.returncode, p.stderr


class Engagement:
    def __init__(self, store: Store, operator=None, allow_exec=True):
        self.store, self.allow_exec = store, allow_exec
        store.require()
        self.op = store.operator(operator)
        self.clock = None  # set by the demo to date events in the past; normal use leaves it alone
        self.cfg = store.cfg()
        try:
            self.scope = Scope.load(store.scope_path) if store.scope_path.exists() else None
        except ScopeError as e:
            raise OpsError(str(e))

    def _ap(self, kind, data, operator=None, ref_prefix=None):
        return self.store.append(kind, data, operator, at=self.clock, ref_prefix=ref_prefix)

    # ---- state and guards
    def state(self):
        return build(self.store)

    def _active(self, st):
        if st.frozen:
            raise OpsError(f"engagement is FROZEN ({st.freeze_info['reason']}). Only rollback, containment, SITREP, decisions and evidence "
                           "handling are allowed. The Control Team resumes with `redsweep resume --approved-by NAME`.")

    def _guard(self, host, cls=None, override=None, at=None):
        """Scope, window and forbidden-action checks. Returns the override reason if one was needed and given."""
        if not self.scope:
            return None
        problems = []
        if host:
            v, why = self.scope.check(host)
            if v == "out" or (v == "unlisted" and self.cfg["strict_scope"]):
                problems.append(f"{host}: {why}")
        if cls:
            v, why = self.scope.check_action(cls)
            if v == "forbidden":
                problems.append(why)
        ok, why = self.scope.check_window(at)
        if not ok:
            problems.append(why)
        if problems:
            if not override:
                raise OpsError("refused by the rules of engagement: " + "; ".join(problems) +
                               ". If the Control Team approved it, repeat with --scope-override 'who approved and why'.")
            return override
        return None

    def _tripwire(self, st, tripwire, decision):
        if not tripwire:
            return
        if self.scope and tripwire not in self.scope.tripwires:
            raise OpsError(f"unknown tripwire {tripwire!r}; this engagement defines {self.scope.tripwires}")
        if not decision:
            raise OpsError(f"tripwire {tripwire!r}: the Control Team must decide first. Record it with `redsweep decide ... --tag {tripwire}` and pass --decision ID.")
        _, d = self._find_decision(st, decision)
        if tripwire not in (d.get("tags") or []):
            raise OpsError(f"decision {decision} does not cover tripwire {tripwire!r}")

    def _find_decision(self, st, ref):
        table = {d["id"]: d for d in st.decisions}
        try:
            return st.find(table, ref, "decision")
        except RefError as e:
            raise OpsError(str(e))

    # ---- operator log
    def log_action(self, text, host=None, layer="n/a", result="ok", assumption=None, new_info=False, cls=None, override=None,
                   tripwire=None, decision=None, cmd=None, exit_code=None, out_sha=None, at=None, imported=False, tags=None, intent=None, import_key=None):
        st = self.state()
        if host or imported is False and cls:  # notes with no target contact are allowed while frozen; anything that touches a target is not
            self._active(st)
        if layer not in ERROR_LAYERS:
            raise OpsError(f"layer must be one of {ERROR_LAYERS}")
        if result not in ("ok", "fail", "partial", "planned"):
            raise OpsError("result must be ok, fail, partial or planned")
        if not imported:
            ov = self._guard(host, cls, override, at or self.clock)
            self._tripwire(st, tripwire, decision)
        else:
            ov = None
        d = {"text": text, "host": host, "layer": layer, "result": result, "assumption": assumption, "new_info": bool(new_info), "class": cls,
             "scope_override": ov, "tripwire": tripwire, "decision": decision, "cmd": cmd, "exit": exit_code, "out_sha": out_sha,
             "imported": imported, "tags": tags or [], "at": iso(parse_time(at)) if at else None, "intent": intent, "import_key": import_key}
        ev = self._ap("action", {k: v for k, v in d.items() if v not in (None, [], False) or k in ("new_info",)}, self.op, ref_prefix="A-")
        warn = None
        if assumption:
            st2 = self.state()
            if st2.warnings and "assumption" in st2.warnings[-1] and assumption.strip().lower() in st2.warnings[-1].lower():
                warn = st2.warnings[-1]
        return ev, warn

    # ---- change ledger
    def add_change(self, kind, host, obj, change, original=None, original_file=None, capture=None, ignore=None, created=False,
                   rollback_plan="", rollback_cmd=None, autonomous=None, etag=None, secret=False, override=None, tripwire=None,
                   decision=None, tags=None, at=None, timeout=30):
        if kind not in CHANGE_KINDS:
            raise OpsError(f"kind must be one of {sorted(CHANGE_KINDS)}")
        st = self.state()
        self._active(st)
        ov = self._guard(host, None, override, at or self.clock)
        self._tripwire(st, tripwire, decision)
        if capture:
            if not self.allow_exec:
                raise OpsError("running capture commands is disabled in this mode")
            text, rc, err = run_shell(capture, timeout)
        elif original_file:
            text = Path(original_file).read_text(errors="replace")
        elif original is not None:
            text = original
        elif created:
            text = "<absent>"
        else:
            raise OpsError("record the original value before you change anything: use --capture CMD (best), --original-file F, --original TEXT, "
                           "or --created if the object did not exist before")
        norm = normalize(text, ignore)
        display, protected = protect(norm, force=secret)
        if len(display) > 2000:
            display = display[:2000] + "…[cut]"
        d = {"kind": kind, "host": host, "object": obj, "change": change, "original_display": display, "original_sha": sha256_text(norm),
             "protected": protected, "capture": capture, "ignore": ignore or [], "created": bool(created), "rollback_plan": rollback_plan,
             "rollback_cmd": rollback_cmd, "autonomous": bool(autonomous if autonomous is not None else kind in AUTONOMOUS_KINDS),
             "etag": etag, "scope_override": ov, "tripwire": tripwire, "decision": decision, "tags": tags or []}
        if at:
            d["at"] = iso(parse_time(at))
        return self._ap("change.add", d, self.op, ref_prefix="C-")

    def _change(self, st, ref):
        try:
            return st.find(st.changes, ref, "change")
        except RefError as e:
            raise OpsError(str(e))

    def rollback(self, ref, how=None, run=False, durable=None, verify=False, timeout=60):
        st = self.state()
        cid, c = self._change(st, ref)
        if c["status"] == "waived":
            raise OpsError(f"{cid} is waived")
        exit_code = None
        if run:
            if not self.allow_exec:
                raise OpsError("running commands is disabled in this mode")
            if not c.get("rollback_cmd"):
                raise OpsError(f"{cid} has no rollback command; add one with --rollback-cmd when you record the change, or roll back by hand and drop --run")
            out, exit_code, err = run_shell(c["rollback_cmd"], timeout)
            if exit_code != 0:
                raise OpsError(f"rollback command for {cid} exited {exit_code}: {short(err or out, 200)}. Nothing was recorded.")
            how = how or f"ran: {c['rollback_cmd']}"
        if not how:
            raise OpsError("say how you rolled it back (--how TEXT), or use --run to execute the stored rollback command")
        ev = self._ap("change.rollback", {"ref": cid, "how": how, "exit": exit_code, "durable": durable}, self.op)
        res = None
        if verify:
            res = self.verify(cid)
        return ev, res

    def verify(self, ref, readback_value=None, readback_file=None, note=None, attest=False, force=False, timeout=30):
        st = self.state()
        cid, c = self._change(st, ref)
        if c["status"] == "applied" and not force:
            raise OpsError(f"{cid} has not been rolled back yet. Roll it back first (`redsweep change rollback {cid}`).")
        if c["status"] == "waived":
            raise OpsError(f"{cid} is waived")
        r = c.get("rolled_by")
        if self.cfg.get("require_second_operator") and r and r["op"] == self.op:
            raise OpsError(f"this engagement requires a second operator for read-backs; {cid} was rolled back by {self.op}")
        sha, strength, result = None, None, None
        if attest:
            if not note:
                raise OpsError("an attested check needs --note saying what you looked at")
            strength, result = "attested", "match"
        else:
            if readback_value is not None:
                text, strength = readback_value, "manual"
            elif readback_file:
                text, strength = Path(readback_file).read_text(errors="replace"), "manual"
            elif c.get("capture"):
                if not self.allow_exec:
                    raise OpsError("running capture commands is disabled in this mode; pass --readback-value or --readback-file")
                text, rc, err = run_shell(c["capture"], timeout)
                strength = "auto"
            else:
                raise OpsError(f"{cid} has no capture command; pass --readback-value/--readback-file, or --attest --note TEXT for a human attestation")
            sha = sha256_text(normalize(text, c.get("ignore")))
            result = "match" if sha == c["original_sha"] else "mismatch"
        if STRENGTH_RANK[strength] < STRENGTH_RANK.get(self.cfg["min_verify_strength"], 1):
            raise OpsError(f"this engagement requires at least a {self.cfg['min_verify_strength']!r} read-back; got {strength!r}")
        ev = self._ap("change.verify", {"ref": cid, "result": result, "strength": strength, "note": note, "readback_sha": sha}, self.op)
        return {"id": cid, "result": result, "strength": strength, "event": ev}

    def waive(self, ref, reason, by):
        st = self.state()
        cid, c = self._change(st, ref)
        if not reason or not by:
            raise OpsError("a waiver needs --reason and --by (who accepted the residual risk)")
        return self._ap("change.waive", {"ref": cid, "reason": reason, "by": by}, self.op)

    # ---- credentials
    def add_cred(self, family, principal, label="", material=None, material_file=None, location="", host=None, issued_latest=None,
                 lifetime=None, override=None, steps=None):
        if family not in FAMILIES:
            raise OpsError(f"family must be one of {sorted(FAMILIES)}")
        st = self.state()
        self._active(st)
        ov = self._guard(host, None, override)
        sha, ln = None, 0
        if material_file:
            sha, ln = sha256_file(material_file), os.path.getsize(material_file)
        elif material is not None:
            sha, ln = sha256_text(material), len(material)
        issued = parse_time(issued_latest) if issued_latest else now()
        lt = lifetime if lifetime is not None else FAMILIES[family]["lifetime"]
        d = {"family": family, "principal": principal, "label": label, "material_sha": sha, "material_len": ln, "location": location,
             "host": host, "issued_latest": iso(issued), "lifetime": lt,
             "window_end": iso(issued + dt.timedelta(seconds=lt)) if lt else None, "scope_override": ov}
        if steps:
            d["steps"] = steps
        return self._ap("cred.add", d, self.op, ref_prefix="K-")

    def cred_step(self, ref, step, note=""):
        st = self.state()
        try:
            cid, c = st.find(st.creds, ref, "credential")
        except RefError as e:
            raise OpsError(str(e))
        n = int(step)
        if not 1 <= n <= len(c["steps"]):
            raise OpsError(f"{cid} has steps 1..{len(c['steps'])}")
        return self._ap("cred.step", {"ref": cid, "step": n, "note": note}, self.op)

    def cred_window(self, ref, reason, by):
        st = self.state()
        try:
            cid, c = st.find(st.creds, ref, "credential")
        except RefError as e:
            raise OpsError(str(e))
        if not reason or not by:
            raise OpsError("accepting an open token window needs --reason and --by")
        return self._ap("cred.window", {"ref": cid, "reason": reason, "by": by}, self.op)

    # ---- evidence custody
    def add_evidence(self, path, label, ladder="metadata", host=None, approved_by=None, copy=False):
        if ladder not in LADDER:
            raise OpsError(f"ladder must be one of {LADDER}")
        if ladder == "real-record":
            ct = (self.scope.roles.get("control_team") if self.scope else None) or []
            if not approved_by or (ct and approved_by not in ct):
                raise OpsError("real customer records need approval from a named Control Team member (--approved-by)")
        p = Path(path)
        if not p.is_file():
            raise OpsError(f"{path}: not a file")
        d = {"path": str(p), "label": label, "ladder": ladder, "host": host, "approved_by": approved_by,
             "sha256": sha256_file(p), "size": p.stat().st_size, "copied": None}
        if copy:
            dest = self.store.home / "evidence"
            dest.mkdir(exist_ok=True, mode=0o700)
            target = dest / f"{d['sha256'][:12]}-{p.name}"
            shutil.copy2(p, target)
            os.chmod(target, 0o600)
            d["copied"] = str(target.relative_to(self.store.home))
        return self._ap("evidence.add", d, self.op, ref_prefix="E-")

    def handoff(self, ref, to, purpose):
        st = self.state()
        try:
            eid, e = st.find(st.evidence, ref, "evidence item")
        except RefError as x:
            raise OpsError(str(x))
        return self._ap("evidence.handoff", {"ref": eid, "to": to, "purpose": purpose}, self.op)

    def destroy(self, ref, method, witness, delete=False):
        st = self.state()
        try:
            eid, e = st.find(st.evidence, ref, "evidence item")
        except RefError as x:
            raise OpsError(str(x))
        if not method or not witness:
            raise OpsError("a destruction record needs --method and --witness")
        sha = e["sha256"]
        for p in (e.get("path"), (self.store.home / e["copied"]) if e.get("copied") else None):
            if delete and p and Path(p).is_file():
                sha = sha256_file(p)  # hash what is really there, then remove it
                Path(p).unlink()
        return self._ap("evidence.destroy", {"ref": eid, "method": method, "witness": witness, "sha256_before": sha, "deleted_by_tool": bool(delete)}, self.op)

    def canary_make(self, label):
        marker = "LT-" + secrets.token_hex(8)
        rec = {"canary": marker, "label": label, "note": "synthetic record planted for an authorised test", "id": secrets.token_hex(4)}
        return rec, sha256_text(canon(rec))

    def canary_check(self, data: str, expect_sha: str, label=""):
        st = self.state()
        self._active(st)
        digest = sha256_text(data.strip())
        alt = None
        if data.strip().startswith("{"):
            try:
                alt = sha256_text(canon(json.loads(data)))
            except ValueError:
                pass
        want = expect_sha.lower()
        match = want in (digest, alt)
        digest = want if match else digest
        ev = self._ap("canary.proof", {"label": label, "expected": expect_sha.lower(), "observed": digest, "match": match}, self.op)
        return match, ev

    # ---- detection, freeze, decisions
    def detect(self, level, host=None, evidence="", source="", at=None, action=None):
        levels = self.cfg["levels"]
        if level not in levels:
            raise OpsError(f"level must be one of {sorted(levels)}")
        return self._ap("detect", {"level": level, "host": host, "evidence": evidence, "source": source, "action": action,
                                            "at": iso(parse_time(at)) if at else None}, self.op, ref_prefix="X-")

    def freeze(self, reason, condition=None):
        if condition and condition not in STOP_CONDITIONS:
            raise OpsError(f"stop condition must be one of {sorted(STOP_CONDITIONS)}")
        st = self.state()
        if st.frozen and not condition:
            raise OpsError("already frozen")
        return self._ap("freeze", {"reason": reason, "condition": condition}, self.op)

    def resume(self, approved_by, decision=None):
        st = self.state()
        if not st.frozen:
            raise OpsError("the engagement is not frozen")
        if self.scope and not self.scope.is_ct(approved_by):
            raise OpsError(f"{approved_by!r} is not on the Control Team list; red team recommends, the Control Team decides")
        if any(not s["cleared"] for s in st.stops) and not decision:
            raise OpsError("a stop condition is open: resuming needs --decision ID from the Control Team")
        if decision:
            self._find_decision(st, decision)
        return self._ap("resume", {"approved_by": approved_by, "decision": decision}, self.op)

    def recommend(self, recommended, rationale, options=None):
        for o in [recommended] + list(options or []):
            if o not in DECISION_OPTIONS:
                raise OpsError(f"option must be one of {DECISION_OPTIONS}")
        return self._ap("recommend", {"recommended": recommended, "options": options or [], "rationale": rationale}, self.op, ref_prefix="R-")

    def decide(self, chosen, decider, rationale, tags=None, options=None, recommended_by=None):
        if chosen not in DECISION_OPTIONS:
            raise OpsError(f"decision must be one of {DECISION_OPTIONS}")
        if self.scope and not self.scope.is_ct(decider):
            raise OpsError(f"{decider!r} is not on the Control Team list in scope.json. The red team recommends; the Control Team decides.")
        if not rationale:
            raise OpsError("write down why (--rationale)")
        for t in tags or []:
            if self.scope and t not in self.scope.tripwires:
                raise OpsError(f"unknown tag {t!r}; this engagement defines {self.scope.tripwires}")
        return self._ap("decision", {"chosen": chosen, "decider": decider, "rationale": rationale, "tags": tags or [],
                                              "options": options or [], "recommended_by": recommended_by}, self.op, ref_prefix="D-")

    def note(self, text):
        return self._ap("note", {"text": text}, self.op)

    # ---- teardown plan (derived, never stored)
    def teardown_plan(self, st=None):
        st = st or self.state()
        steps = []
        for c in st.changes.values():
            if c["status"] == "waived":
                done, why = True, "waived: " + str((c["waiver"] or {}).get("reason"))
            else:
                done = c["status"] == "verified"
                why = {"applied": "not rolled back", "rolled_back": "rolled back, read-back missing", "mismatch": "read-back does not match the original"}.get(c["status"], "")
            order = TEARDOWN_ORDER.index(c["kind"]) if c["kind"] in TEARDOWN_ORDER else len(TEARDOWN_ORDER)
            steps.append({"order": order, "ref": c["id"], "area": c["kind"], "host": c.get("host"), "text": f"{c['kind']}: {c['object']}", "done": done, "why": why if not done else ""})
        for c in st.creds.values():
            s, wopen, wend = st.cred_status(c)
            why = f"{len(c['steps_done'])}/{len(c['steps'])} steps done" + (f"; token window open until {iso(wend)}" if wopen else "")
            steps.append({"order": TEARDOWN_ORDER.index("account") + 0.5, "ref": c["id"], "area": "credential", "host": c.get("host"),
                          "text": f"credential {c['family']} for {c['principal']}", "done": s == "confirmed", "why": "" if s == "confirmed" else why})
        for e in st.evidence.values():
            done = bool(e["destroyed"] or e["handoffs"])
            steps.append({"order": TEARDOWN_ORDER.index("data") + 0.5, "ref": e["id"], "area": "evidence", "host": e.get("host"),
                          "text": f"evidence {e['label']} ({e['ladder']})", "done": done, "why": "" if done else "neither handed over nor destroyed"})
        steps.sort(key=lambda s: (s["order"], s["ref"]))
        return steps
