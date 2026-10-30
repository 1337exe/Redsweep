"""MCP server (stdio, newline-delimited JSON-RPC). It lets an AI agent that works on an engagement record what it does and obey the rules.
The agent can log, record changes, roll back, read back and check closeout. It cannot waive, decide, resume or run shell commands."""
from __future__ import annotations

import json
import sys

from . import __version__, pricing
from .closeout import blockers, check
from .model import CHANGE_KINDS, ERROR_LAYERS
from .ops import Engagement, OpsError

S = lambda props, req=(): {"type": "object", "properties": props, "required": list(req)}
STR = {"type": "string"}
TOOLS = [
    ("redsweep_status", "Read the engagement state first: frozen or not, open changes, open credentials, warnings. If frozen, stop acting.", S({})),
    ("redsweep_scope_check", "Check a host, URL or account against the rules of engagement BEFORE touching it. Do not act on 'out' or 'unlisted'.",
     S({"target": STR, "action_class": STR}, ["target"])),
    ("redsweep_price", "Look up what an action class leaves behind and where it is recorded, before you run it.", S({"action_class": STR}, ["action_class"])),
    ("redsweep_log_action", "Record an action in the operator log. Record failures and dead ends too. Name the assumption you tested. Refused if the target is out of scope or the engagement is frozen.",
     S({"text": STR, "host": STR, "layer": {"type": "string", "enum": ERROR_LAYERS}, "result": {"type": "string", "enum": ["ok", "fail", "partial", "planned"]},
        "assumption": STR, "new_information": {"type": "boolean"}, "action_class": STR}, ["text"])),
    ("redsweep_change_add", "Record a change to a target BEFORE you make it, with its original value. Without the original value the call is refused.",
     S({"kind": {"type": "string", "enum": sorted(CHANGE_KINDS)}, "host": STR, "object": STR, "change": STR, "original_value": STR,
        "created": {"type": "boolean"}, "rollback_plan": STR}, ["kind", "host", "object", "change"])),
    ("redsweep_change_rollback", "Record that you rolled a change back, and how. This does not close it; a read-back must follow.",
     S({"ref": STR, "how": STR, "durable_control_remaining": STR}, ["ref", "how"])),
    ("redsweep_change_verify", "Read the state back AFTER rollback and pass the value you read. It is compared with the original value.",
     S({"ref": STR, "readback_value": STR}, ["ref", "readback_value"])),
    ("redsweep_closeout_check", "List everything that still blocks closing the engagement. Run it before you say you are done.", S({})),
]


def _text(o):
    return {"content": [{"type": "text", "text": o if isinstance(o, str) else json.dumps(o, indent=2, default=str)}]}


def call(eng: Engagement, name: str, a: dict):
    if name == "redsweep_status":
        st = eng.state()
        items = check(eng)
        return {"frozen": st.frozen, "freeze_reason": (st.freeze_info or {}).get("reason"), "actions": len(st.actions),
                "open_changes": [f"{c['id']} {c['kind']} {c['object']} [{c['status']}]" for c in st.active_changes()],
                "blockers": len(blockers(items)), "warnings": st.warnings}
    if name == "redsweep_scope_check":
        if not eng.scope:
            return {"verdict": "unlisted", "why": "no scope file"}
        v, why = eng.scope.check(a["target"])
        res = {"target": a["target"], "verdict": v, "why": why}
        if a.get("action_class"):
            res["action"] = eng.scope.check_action(a["action_class"])[0]
        ok, w = eng.scope.check_window()
        res["in_window"] = ok
        return res
    if name == "redsweep_price":
        return pricing.explain(a["action_class"])
    if name == "redsweep_log_action":
        ev, warn = eng.log_action(a["text"], host=a.get("host"), layer=a.get("layer", "n/a"), result=a.get("result", "ok"),
                                  assumption=a.get("assumption"), new_info=a.get("new_information", False), cls=a.get("action_class"))
        return {"recorded": ev["id"], "warning": warn}
    if name == "redsweep_change_add":
        ev = eng.add_change(a["kind"], a.get("host"), a["object"], a["change"], original=a.get("original_value"), created=a.get("created", False),
                            rollback_plan=a.get("rollback_plan", ""))
        return {"recorded": ev["id"], "next": "make the change, then later roll it back and read it back"}
    if name == "redsweep_change_rollback":
        ev, _ = eng.rollback(a["ref"], how=a["how"], durable=a.get("durable_control_remaining"))
        return {"recorded": True, "next": "now read the state back and call redsweep_change_verify"}
    if name == "redsweep_change_verify":
        r = eng.verify(a["ref"], readback_value=a["readback_value"])
        return {"change": r["id"], "result": r["result"], "strength": r["strength"]}
    if name == "redsweep_closeout_check":
        items = check(eng)
        return {"clean": not blockers(items), "items": items}
    raise KeyError(name)


def handle(eng: Engagement, msg: dict):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None
    ok = lambda r: {"jsonrpc": "2.0", "id": mid, "result": r}
    if method == "initialize":
        return ok({"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2024-11-05"), "capabilities": {"tools": {}},
                   "serverInfo": {"name": "redsweep", "version": __version__}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": [{"name": n, "description": d, "inputSchema": s} for n, d, s in TOOLS]})
    if method == "tools/call":
        p = msg.get("params") or {}
        if p.get("name") not in {t[0] for t in TOOLS}:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        try:
            return ok(_text(call(eng, p["name"], p.get("arguments") or {})))
        except (OpsError, KeyError, ValueError) as e:
            return ok({"isError": True, "content": [{"type": "text", "text": f"refused: {e}"}]})
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def serve(eng: Engagement, stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        resp = handle(eng, msg)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
