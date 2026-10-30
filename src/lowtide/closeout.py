"""The closeout gate: an engagement is closed only when everything it changed is undone and proved undone."""
from __future__ import annotations

import html

from .model import STRENGTH_RANK
from .ops import Engagement
from .util import iso, now, short


def check(eng: Engagement, at=None):
    """-> list of {sev, area, ref, msg}. Any `blocker` stops closeout."""
    st = eng.state()
    at = at or now()
    out = []

    def add(sev, area, ref, msg):
        out.append({"sev": sev, "area": area, "ref": ref, "msg": msg})
    for p in st.problems:
        add("blocker", "journal", "", "journal fails its hash check: " + p)
    if st.frozen:
        add("blocker", "freeze", "", f"engagement is frozen ({st.freeze_info['reason']}); the Control Team must resume or end it")
    for s in st.stops:
        if not s["cleared"]:
            add("blocker", "stop", "", f"stop condition {s['condition']!r} was never cleared by a Control Team decision")
    for c in st.changes.values():
        stt = c["status"]
        if stt == "applied":
            add("blocker", "ledger", c["id"], f"{c['kind']} '{short(c['object'], 60)}' on {c.get('host') or '?'} is still in place (never rolled back)")
        elif stt == "rolled_back":
            add("blocker", "ledger", c["id"], f"{c['kind']} '{short(c['object'], 60)}' was rolled back but never read back")
        elif stt == "mismatch":
            add("blocker", "ledger", c["id"], f"read-back of '{short(c['object'], 60)}' does not match the original value")
        elif stt == "verified":
            v = c["verify"] or {}
            if STRENGTH_RANK.get(v.get("strength"), 0) < STRENGTH_RANK.get(eng.cfg["min_verify_strength"], 1):
                add("blocker", "ledger", c["id"], f"read-back strength {v.get('strength')} is below the required {eng.cfg['min_verify_strength']}")
            elif v.get("strength") == "attested":
                add("warn", "ledger", c["id"], f"'{short(c['object'], 50)}' was cleared by attestation only (nobody compared a value)")
            if c.get("durable"):
                add("info", "ledger", c["id"], f"durable control remains after rollback: {c['durable']}")
        elif stt == "waived":
            add("warn", "ledger", c["id"], f"waived by {c['waiver']['by']}: {c['waiver']['reason']}")
    for k in st.creds.values():
        s, wopen, wend = st.cred_status(k, at)
        if s != "confirmed":
            extra = f"; tokens issued before disabling stay valid until {iso(wend)}" if wopen else ""
            add("blocker", "credentials", k["id"], f"{k['family']} credential for {k['principal']}: containment {s.replace('_', ' ')} "
                f"({len(k['steps_done'])}/{len(k['steps'])} steps){extra}")
        elif k["window_waiver"]:
            add("warn", "credentials", k["id"], f"token window accepted by {k['window_waiver']['by']}: {k['window_waiver']['reason']}")
    for e in st.evidence.values():
        if not (e["destroyed"] or e["handoffs"]):
            add("blocker", "custody", e["id"], f"evidence '{e['label']}' ({e['ladder']}) is neither handed over nor destroyed")
        if e["ladder"] == "real-record" and not e.get("approved_by"):
            add("blocker", "custody", e["id"], "a real record is held with no Control Team approval on file")
    for w in st.warnings:
        add("warn", "log", "", w)
    for o in st.overrides:
        add("info", "scope", o["ref"] or "", f"scope override by {o['op']} for {o['target']}: {o['reason']}")
    fails = [a for a in st.actions if a.get("result") == "fail"]
    n_real = [a for a in st.actions if a.get("result") in ("ok", "fail", "partial")]
    if len(n_real) >= 10 and not fails:
        add("warn", "log", "", f"{len(n_real)} actions logged and not one failure. A log with only successes cannot be checked; record the dead ends too")
    if not st.actions:
        add("warn", "log", "", "the operator log is empty")
    return out


def blockers(items):
    return [i for i in items if i["sev"] == "blocker"]


# ---------- reports
def report_data(eng: Engagement, items=None):
    st = eng.state()
    items = items if items is not None else check(eng)
    plan = eng.teardown_plan(st)
    return {
        "engagement": st.meta, "generated": iso(now()), "operators": sorted({e["op"] for e in st.actions} | {c["op"] for c in st.changes.values()}),
        "closed_ok": not blockers(items), "findings": items,
        "counts": {"actions": len(st.actions), "failures": sum(1 for a in st.actions if a.get("result") == "fail"),
                   "changes": len(st.changes), "verified": sum(1 for c in st.changes.values() if c["status"] == "verified"),
                   "credentials": len(st.creds), "evidence": len(st.evidence), "decisions": len(st.decisions),
                   "sitreps": len(st.sitreps), "detections": len(st.detections), "overrides": len(st.overrides)},
        "changes": list(st.changes.values()), "credentials": [dict(k, status=st.cred_status(k)[0]) for k in st.creds.values()],
        "evidence": list(st.evidence.values()), "decisions": st.decisions, "recommendations": st.recommendations, "sitreps": st.sitreps,
        "detections": st.detections, "freezes": st.freezes, "overrides": st.overrides, "teardown": plan,
        "actions": st.actions, "canaries": st.canaries,
    }


def to_markdown(r) -> str:
    m = r["engagement"]
    L = [f"# Closeout report: {m.get('name', 'engagement')}", ""]
    L.append(f"Client: {m.get('client') or '-'} · Generated {r['generated']} (UTC) · Operators: {', '.join(r['operators']) or '-'}")
    L.append("")
    L.append("**Result: " + ("CLEAN. Everything changed was undone and proved undone." if r["closed_ok"] else
             f"NOT CLEAN. {len(blockers(r['findings']))} blocker(s) remain.**"))
    L.append("")
    c = r["counts"]
    L.append(f"{c['actions']} actions logged ({c['failures']} failures recorded) · {c['changes']} changes ({c['verified']} verified) · "
             f"{c['credentials']} credentials · {c['evidence']} evidence items · {c['decisions']} Control Team decisions · {c['detections']} detections")
    L.append("")
    L.append("## Findings from the closeout check\n")
    if not r["findings"]:
        L.append("None.\n")
    for f in r["findings"]:
        L.append(f"- **{f['sev'].upper()}** [{f['area']}] {f['ref']} {f['msg']}")
    L.append("\n## Change ledger\n")
    L.append("| ID | Time (UTC) | Host | Kind | Object | Original value | Rollback | Read-back | Status |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for ch in r["changes"]:
        v = ch.get("verify") or {}
        rb = (ch.get("rolled_by") or {})
        L.append(f"| {ch['id']} | {ch['t']} | {ch.get('host') or ''} | {ch['kind']} | {short(ch['object'], 50)} | "
                 f"{short(ch['original_display'], 40).replace('|', '/')} | {rb.get('t', '-')} by {rb.get('op', '-')} | "
                 f"{v.get('result', '-')} ({v.get('strength', '-')}) {v.get('t', '')} | {ch['status']} |")
    L.append("\n## Credentials\n")
    L.append("| ID | Family | Principal | Token window ends (UTC) | Steps | Status |")
    L.append("|---|---|---|---|---|---|")
    for k in r["credentials"]:
        L.append(f"| {k['id']} | {k['family']} | {k['principal']} | {k.get('window_end') or '-'} | {len(k['steps_done'])}/{len(k['steps'])} | {k['status']} |")
    L.append("\n## Evidence custody\n")
    L.append("| ID | Label | Ladder | SHA-256 | Handed to | Destroyed |")
    L.append("|---|---|---|---|---|---|")
    for e in r["evidence"]:
        L.append(f"| {e['id']} | {e['label']} | {e['ladder']} | {e['sha256'][:16]}… | {', '.join(h['to'] for h in e['handoffs']) or '-'} | "
                 f"{(e['destroyed'] or {}).get('t', '-')} |")
    L.append("\n## Control Team decisions\n")
    for d in r["decisions"]:
        L.append(f"- {d['t']} **{d['chosen']}** by {d['decider']}: {d['rationale']}" + (f" (tags: {', '.join(d['tags'])})" if d.get("tags") else ""))
    if not r["decisions"]:
        L.append("None recorded.")
    L.append("\n## Detections\n")
    for d in r["detections"]:
        L.append(f"- {d['t']} **{d['level']}** on {d.get('host') or '?'} ({d.get('source') or '-'}): {d.get('evidence') or ''}")
    if not r["detections"]:
        L.append("None recorded.")
    L.append("\n## Scope overrides\n")
    for o in r["overrides"]:
        L.append(f"- {o['t']} {o['op']}: {o['target']} · {o['reason']}")
    if not r["overrides"]:
        L.append("None.")
    L.append("\n## Teardown\n")
    for s in r["teardown"]:
        L.append(f"- [{'x' if s['done'] else ' '}] {s['ref']} {s['text']}" + (f" ({s['why']})" if s["why"] else ""))
    L.append("\n---\nThis report was built from a hash-chained journal. `lowtide verify` checks the chain; `lowtide seal` seals the closeout.\n")
    return "\n".join(L)


_CSS = """:root{--bg:#f7fafb;--fg:#10222b;--mut:#5b6f79;--line:#d5e0e5;--ok:#0f7a52;--bad:#b3261e;--warn:#9a6700;--card:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#0c171c;--fg:#e6f0f3;--mut:#93a8b1;--line:#22363f;--ok:#4ad19b;--bad:#ff8a80;--warn:#e3b341;--card:#122128}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.sub{color:var(--mut)}.banner{padding:14px 16px;border-radius:8px;margin:16px 0;font-weight:600;border:1px solid var(--line);background:var(--card)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}table{border-collapse:collapse;width:100%;background:var(--card);font-size:13px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{color:var(--mut);font-weight:600}code{font-size:12px;white-space:nowrap}td:nth-child(2){min-width:0}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--line);font-size:12px}"""


def to_html(r) -> str:
    e = html.escape
    m = r["engagement"]
    ok = r["closed_ok"]
    rows = lambda items: "".join(items)
    ch = rows(f"<tr><td><code>{e(c['id'])}</code></td><td style='white-space:nowrap'>{e(c['t'])}</td><td>{e(c.get('host') or '')}</td><td>{e(c['kind'])}</td><td>{e(short(c['object'], 70))}</td>"
              f"<td><code>{e(short(c['original_display'], 60))}</code></td><td>{e((c.get('rolled_by') or {}).get('t', '-'))}</td>"
              f"<td>{e((c.get('verify') or {}).get('result', '-'))} <span class=sub>{e((c.get('verify') or {}).get('strength', ''))}</span></td>"
              f"<td><span class=pill>{e(c['status'])}</span></td></tr>" for c in r["changes"])
    fi = rows(f"<tr><td class='{ {'blocker':'bad','warn':'warn','info':'sub'}[f['sev']] }'>{e(f['sev'])}</td><td>{e(f['area'])}</td><td><code>{e(f['ref'])}</code></td><td>{e(f['msg'])}</td></tr>" for f in r["findings"])
    cr = rows(f"<tr><td><code>{e(k['id'])}</code></td><td>{e(k['family'])}</td><td>{e(k['principal'])}</td><td>{e(k.get('window_end') or '-')}</td><td>{len(k['steps_done'])}/{len(k['steps'])}</td><td>{e(k['status'])}</td></tr>" for k in r["credentials"])
    ev = rows(f"<tr><td><code>{e(x['id'])}</code></td><td>{e(x['label'])}</td><td>{e(x['ladder'])}</td><td><code>{e(x['sha256'][:20])}…</code></td><td>{e(', '.join(h['to'] for h in x['handoffs']) or '-')}</td><td>{e((x['destroyed'] or {}).get('t', '-'))}</td></tr>" for x in r["evidence"])
    de = rows(f"<tr><td>{e(d['t'])}</td><td>{e(d['chosen'])}</td><td>{e(d['decider'])}</td><td>{e(d['rationale'])}</td></tr>" for d in r["decisions"])
    dt_ = rows(f"<tr><td>{e(d['t'])}</td><td>{e(d['level'])}</td><td>{e(d.get('host') or '')}</td><td>{e(d.get('source') or '')}</td><td>{e(d.get('evidence') or '')}</td></tr>" for d in r["detections"])
    c = r["counts"]
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv=Content-Security-Policy content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
            f"<title>Closeout report: {e(m.get('name', 'engagement'))}</title><style>{_CSS}</style></head><body><main>"
            f"<h1>Closeout report: {e(m.get('name', 'engagement'))}</h1><div class=sub>Client {e(m.get('client') or '-')} · generated {e(r['generated'])} (UTC) · operators {e(', '.join(r['operators']) or '-')}</div>"
            f"<div class=banner><span class='{'ok' if ok else 'bad'}'>{'CLEAN: everything changed was undone and proved undone.' if ok else 'NOT CLEAN: ' + str(len(blockers(r['findings']))) + ' blocker(s) remain.'}</span>"
            f"<div class=sub style='font-weight:400'>{c['actions']} actions ({c['failures']} failures recorded) · {c['changes']} changes ({c['verified']} verified) · {c['credentials']} credentials · "
            f"{c['evidence']} evidence items · {c['decisions']} decisions · {c['detections']} detections</div></div>"
            f"<h2>Closeout check</h2><table><tr><th>Severity<th>Area<th>Ref<th>Finding</tr>{fi or '<tr><td colspan=4>No findings.</td></tr>'}</table>"
            f"<h2>Change ledger</h2><table><tr><th>ID<th>Time (UTC)<th>Host<th>Kind<th>Object<th>Original<th>Rolled back<th>Read-back<th>Status</tr>{ch}</table>"
            f"<h2>Credentials</h2><table><tr><th>ID<th>Family<th>Principal<th>Token window ends<th>Steps<th>Status</tr>{cr or '<tr><td colspan=6>None.</td></tr>'}</table>"
            f"<h2>Evidence custody</h2><table><tr><th>ID<th>Label<th>Ladder<th>SHA-256<th>Handed to<th>Destroyed</tr>{ev or '<tr><td colspan=6>None.</td></tr>'}</table>"
            f"<h2>Control Team decisions</h2><table><tr><th>Time<th>Decision<th>Decider<th>Why</tr>{de or '<tr><td colspan=4>None recorded.</td></tr>'}</table>"
            f"<h2>Detections</h2><table><tr><th>Time<th>Level<th>Host<th>Source<th>Evidence</tr>{dt_ or '<tr><td colspan=5>None recorded.</td></tr>'}</table>"
            f"<p class=sub>Built from a hash-chained journal. Run <code>lowtide verify</code> to check it.</p></main></body></html>")
