"""The control-team side: SITREPs built from the log, and the list of what keeps running after a freeze."""
from __future__ import annotations

from .ops import Engagement, OpsError
from .util import iso, short


def autonomous_list(st):
    out = []
    for c in st.autonomous():
        out.append(f"{c['id']}  {c['kind']} on {c.get('host') or '?'}: {c['object']} ({c['status']})")
    return out


def exposed_list(st):
    """What responders could find next: live changes and credentials that are not yet contained."""
    out = []
    for c in st.active_changes():
        out.append(f"{c['id']}  {c['kind']} on {c.get('host') or '?'}: {short(c['object'], 80)} [{c['status']}]")
    for k in st.creds.values():
        status, wopen, wend = st.cred_status(k)
        if status != "confirmed":
            out.append(f"{k['id']}  credential {k['family']} for {k['principal']} [{status}]" + (f", token valid until {iso(wend)}" if wopen else ""))
    return out


def held_list(st):
    return [f"{e['id']}  {e['label']} ({e['ladder']}, sha256 {e['sha256'][:12]})" for e in st.held_evidence()]


def build_sitrep(eng: Engagement, status, observed, assessed="", ask="", risk="", based_on=None, not_yet="", extra_exposed=None):
    st = eng.state()
    ids = {a["id"] for a in st.actions}
    cited = []
    for ref in based_on or []:
        hit = [i for i in ids if i and i.lower().startswith(ref.lower())]
        if len(hit) != 1:
            raise OpsError(f"log entry {ref!r} not found" if not hit else f"log entry {ref!r} is ambiguous")
        cited.append(hit[0])
    if eng.cfg.get("sitrep_requires_log") and not cited:
        raise OpsError("a SITREP must rest on operator log entries. Cite them with --based-on A-xxxxx[,A-yyyyy] "
                       "(see `redsweep log --list`), so the report matches what was actually done.")
    if not observed or not ask:
        raise OpsError("a SITREP needs --observed and --ask (what do you need from the Control Team?)")
    n = len(st.sitreps) + 1
    d = {"n": n, "status": status, "observed": observed, "assessed": assessed, "ask": ask, "risk": risk, "based_on": cited,
         "exposed": exposed_list(st) + list(extra_exposed or []), "autonomous": autonomous_list(st), "data_held": held_list(st),
         "not_yet": not_yet or ("No operator activity since the freeze." if st.frozen else "State what has NOT been done yet."),
         "frozen": st.frozen}
    ev = eng._ap("sitrep", d, eng.op, ref_prefix="S-")
    return ev, d


def render_sitrep(d, t=None, op=None, eid=None) -> str:
    lines = [f"SITREP {d['n']:02d}" + (f"  ({eid})" if eid else "") + (f"  {t}" if t else "") + (f"  from {op}" if op else ""), ""]

    def block(name, body):
        lines.append(f"{name}:")
        if isinstance(body, list):
            lines.extend(f"  - {b}" for b in body) if body else lines.append("  - none")
        else:
            lines.append(f"  {body or '-'}")
        lines.append("")
    block("STATUS", d.get("status"))
    block("OBSERVED", d.get("observed"))
    block("ASSESSED", d.get("assessed"))
    block("EXPOSED (what responders can reach next)", d.get("exposed"))
    block("NOT YET", d.get("not_yet"))
    block("AUTONOMOUS (still running with no operator)", d.get("autonomous"))
    block("DATA HELD", d.get("data_held"))
    block("ASK", d.get("ask"))
    block("RISK NOTE", d.get("risk"))
    if d.get("based_on"):
        lines.append("Based on operator log entries: " + ", ".join(d["based_on"]))
    return "\n".join(lines).rstrip() + "\n"
