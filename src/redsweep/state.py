"""Rebuild the engagement's state by replaying every event. Nothing is stored twice: the journal is the only source of truth."""
from __future__ import annotations

from .model import AUTONOMOUS_KINDS, FAMILIES
from .util import now, parse_time


class RefError(Exception):
    pass


class State:
    def __init__(self, cfg: dict, problems=None):
        self.cfg = cfg
        self.problems = list(problems or [])
        self.meta = {}
        self.actions, self.notes = [], []
        self.changes, self.creds, self.evidence = {}, {}, {}
        self.decisions, self.recommendations, self.sitreps = [], [], []
        self.detections, self.stops, self.freezes, self.canaries = [], [], [], []
        self.overrides, self.imports, self.warnings = [], [], []
        self.frozen, self.freeze_info = False, None
        self.event_count, self.first_t, self.last_t = 0, None, None
        self._assump = {}

    # ---- lookup by short id or unique prefix
    def find(self, table: dict, ref: str, what: str):
        ref = (ref or "").strip()
        if ref in table:
            return ref, table[ref]
        hits = [k for k in table if k.lower().startswith(ref.lower())] if len(ref) >= 2 else []
        if len(hits) == 1:
            return hits[0], table[hits[0]]
        if not hits:
            raise RefError(f"no {what} matches {ref!r}")
        raise RefError(f"{ref!r} matches several {what}s: {', '.join(sorted(hits)[:6])}; use more characters")

    # ---- replay
    def apply(self, ev: dict):
        self.event_count += 1
        self.first_t = self.first_t or ev["t"]
        self.last_t = ev["t"]
        fn = getattr(self, "_on_" + ev["kind"].replace(".", "_"), None)
        if fn:
            fn(ev, ev.get("data") or {})

    def _on_init(self, ev, d):
        self.meta = dict(d, created=ev["t"], created_by=ev["op"])

    def _on_note(self, ev, d):
        self.notes.append({"t": ev["t"], "op": ev["op"], "text": d.get("text", "")})

    def _on_action(self, ev, d):
        a = dict(d, id=ev.get("id"), t=d.get("at") or ev["t"], op=ev["op"], recorded=ev["t"])
        self.actions.append(a)
        if d.get("scope_override"):
            self.overrides.append({"t": ev["t"], "op": ev["op"], "ref": ev.get("id"), "target": d.get("host"), "reason": d["scope_override"]})
        key = (d.get("assumption") or "").strip().lower()
        if key:
            n = self._assump.get(key, 0)
            if d.get("result") == "fail" and not d.get("new_info"):
                n += 1
            elif d.get("result") == "ok" or d.get("new_info"):
                n = 0
            self._assump[key] = n
            if n >= self.cfg.get("assumption_stop_after", 2):
                self.warnings.append(f"assumption {d.get('assumption')!r} failed {n} times with no new information (last at {ev['t']}): "
                                     "stop, write down why, and change the path")

    def _on_change_add(self, ev, d):
        c = dict(d, id=ev.get("id"), t=ev["t"], op=ev["op"], status="applied", history=[("applied", ev["t"], ev["op"])],
                 rolled_by=None, verify=None, waiver=None, durable=None)
        self.changes[c["id"]] = c
        if d.get("scope_override"):
            self.overrides.append({"t": ev["t"], "op": ev["op"], "ref": c["id"], "target": d.get("host"), "reason": d["scope_override"]})

    def _on_change_rollback(self, ev, d):
        try:
            cid, c = self.find(self.changes, d.get("ref"), "change")
        except RefError:
            self.warnings.append(f"rollback at {ev['t']} refers to unknown change {d.get('ref')!r}")
            return
        if c["status"] in ("waived",):
            return
        if c["status"] != "verified":
            c["status"] = "rolled_back"
        c["rolled_by"] = {"op": ev["op"], "t": ev["t"], "how": d.get("how"), "exit": d.get("exit")}
        if d.get("durable"):
            c["durable"] = d["durable"]
        c["history"].append(("rolled_back", ev["t"], ev["op"]))

    def _on_change_verify(self, ev, d):
        try:
            cid, c = self.find(self.changes, d.get("ref"), "change")
        except RefError:
            self.warnings.append(f"verify at {ev['t']} refers to unknown change {d.get('ref')!r}")
            return
        c["verify"] = {"op": ev["op"], "t": ev["t"], "result": d.get("result"), "strength": d.get("strength"), "note": d.get("note"),
                       "readback_sha": d.get("readback_sha"), "second_operator": c["rolled_by"] is None or c["rolled_by"]["op"] != ev["op"]}
        if c["status"] != "waived":
            c["status"] = "verified" if d.get("result") == "match" else "mismatch"
        c["history"].append((c["status"], ev["t"], ev["op"]))

    def _on_change_waive(self, ev, d):
        try:
            cid, c = self.find(self.changes, d.get("ref"), "change")
        except RefError:
            return
        c["status"] = "waived"
        c["waiver"] = {"op": ev["op"], "t": ev["t"], "reason": d.get("reason"), "by": d.get("by")}
        c["history"].append(("waived", ev["t"], ev["op"]))

    def _on_cred_add(self, ev, d):
        fam = FAMILIES.get(d.get("family"), FAMILIES["other"])
        self.creds[ev["id"]] = dict(d, id=ev["id"], t=ev["t"], op=ev["op"], steps_done={}, window_waiver=None, steps=list(d.get("steps") or fam["steps"]))

    def _on_cred_step(self, ev, d):
        try:
            cid, c = self.find(self.creds, d.get("ref"), "credential")
        except RefError:
            return
        c["steps_done"][int(d["step"])] = {"t": ev["t"], "op": ev["op"], "note": d.get("note", "")}

    def _on_cred_window(self, ev, d):
        try:
            cid, c = self.find(self.creds, d.get("ref"), "credential")
        except RefError:
            return
        c["window_waiver"] = {"t": ev["t"], "op": ev["op"], "reason": d.get("reason"), "by": d.get("by")}

    def _on_evidence_add(self, ev, d):
        self.evidence[ev["id"]] = dict(d, id=ev["id"], t=ev["t"], op=ev["op"], handoffs=[], destroyed=None)

    def _on_evidence_handoff(self, ev, d):
        try:
            eid, e = self.find(self.evidence, d.get("ref"), "evidence item")
        except RefError:
            return
        e["handoffs"].append({"t": ev["t"], "op": ev["op"], "to": d.get("to"), "purpose": d.get("purpose")})

    def _on_evidence_destroy(self, ev, d):
        try:
            eid, e = self.find(self.evidence, d.get("ref"), "evidence item")
        except RefError:
            return
        e["destroyed"] = {"t": ev["t"], "op": ev["op"], "method": d.get("method"), "witness": d.get("witness"), "sha256_before": d.get("sha256_before")}

    def _on_canary_proof(self, ev, d):
        self.canaries.append(dict(d, t=ev["t"], op=ev["op"]))

    def _on_detect(self, ev, d):
        self.detections.append(dict(d, id=ev.get("id"), t=d.get("at") or ev["t"], op=ev["op"]))

    def _on_freeze(self, ev, d):
        self.frozen = True
        self.freeze_info = {"t": ev["t"], "op": ev["op"], "reason": d.get("reason"), "condition": d.get("condition")}
        self.freezes.append(dict(self.freeze_info, kind="stop" if d.get("condition") else "freeze"))
        if d.get("condition"):
            self.stops.append({"t": ev["t"], "op": ev["op"], "condition": d["condition"], "detail": d.get("reason"), "cleared": None})

    def _on_resume(self, ev, d):
        self.frozen, self.freeze_info = False, None
        for s in self.stops:
            if not s["cleared"]:
                s["cleared"] = {"t": ev["t"], "by": d.get("approved_by"), "decision": d.get("decision")}
        self.freezes.append({"t": ev["t"], "op": ev["op"], "kind": "resume", "approved_by": d.get("approved_by"), "decision": d.get("decision")})

    def _on_recommend(self, ev, d):
        self.recommendations.append(dict(d, id=ev.get("id"), t=ev["t"], op=ev["op"]))

    def _on_decision(self, ev, d):
        self.decisions.append(dict(d, id=ev.get("id"), t=ev["t"], op=ev["op"]))

    def _on_sitrep(self, ev, d):
        self.sitreps.append(dict(d, id=ev.get("id"), t=ev["t"], op=ev["op"]))

    def _on_import(self, ev, d):
        self.imports.append(dict(d, t=ev["t"], op=ev["op"]))

    # ---- derived views
    def active_changes(self):
        return [c for c in self.changes.values() if c["status"] in ("applied", "rolled_back", "mismatch")]

    def autonomous(self):
        """What keeps running with no operator: the list a Control Team must decide on after a freeze."""
        return [c for c in self.active_changes() if c.get("autonomous") or c.get("kind") in AUTONOMOUS_KINDS]

    def cred_status(self, c, at=None):
        at = at or now()
        done = len(c["steps_done"])
        total = len(c["steps"])
        win_end = parse_time(c["window_end"]) if c.get("window_end") else None
        window_open = bool(win_end and at < win_end and not c["window_waiver"])
        if done == 0:
            st = "not_started"
        elif done < total or window_open:
            st = "in_progress"
        else:
            st = "confirmed"
        return st, window_open, win_end

    def held_evidence(self):
        return [e for e in self.evidence.values() if not e["destroyed"]]


def build(store):
    evs, problems = store.events()
    st = State(store.cfg(), problems)
    for e in evs:
        st.apply(e)
    return st
