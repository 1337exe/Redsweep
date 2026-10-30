"""Purple-team review: line the red operator log up against the blue timeline, in UTC, and score what was seen."""
from __future__ import annotations

import csv
import ipaddress
import json
from pathlib import Path

from . import pricing
from .model import LEVELS
from .util import iso, parse_time, short


class ReviewError(Exception):
    pass


def _pick(row, *names):
    low = {k.lower().strip(): v for k, v in row.items()}
    for n in names:
        if low.get(n) not in (None, ""):
            return low[n]
    return None


def load_blue(path):
    p = Path(path)
    if not p.is_file():
        raise ReviewError(f"{path}: not a file")
    rows = []
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() in (".jsonl", ".ndjson") or text.lstrip().startswith("{"):
        for line in text.splitlines():
            if line.strip():
                rows.append(json.loads(line))
    else:
        rows = list(csv.DictReader(text.splitlines()))
    out = []
    for i, r in enumerate(rows, 1):
        t = _pick(r, "time", "timestamp", "@timestamp", "_time", "date")
        if not t:
            raise ReviewError(f"blue timeline row {i} has no time column (time, timestamp, @timestamp, _time)")
        try:
            tt = parse_time(t)
        except ValueError as e:
            raise ReviewError(f"blue timeline row {i}: {e}")
        out.append({"t": tt, "host": (_pick(r, "host", "hostname", "computer", "device") or "").lower(),
                    "source": _pick(r, "source", "rule", "alert", "detector", "product") or "",
                    "summary": _pick(r, "summary", "message", "title", "description") or "",
                    "level": (_pick(r, "level") or "L1").upper(), "ref": _pick(r, "ref", "ticket", "id") or ""})
    return out


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _host_match(a, b):
    if not a or not b:
        return False
    a, b = a.lower(), b.lower()
    if _is_ip(a) or _is_ip(b):  # addresses must match exactly; "127.0.0.11" is not "127.0.0.12"
        return a == b
    return a == b or a.split(".")[0] == b.split(".")[0]


def review(st, blue, window_min=30):
    acts = [a for a in st.actions if a.get("result") in ("ok", "partial", "fail") and a.get("host")]  # no host = nothing a blue sensor could see; failed attempts still leave logs
    for d in st.detections:  # detections recorded during the engagement count as blue events too
        blue = blue + [{"t": parse_time(d["t"]), "host": (d.get("host") or "").lower(), "source": d.get("source") or "recorded",
                        "summary": d.get("evidence") or "", "level": d["level"], "ref": d.get("id") or "", "action": d.get("action")}]
    # Each blue event is credited to ONE red action: the one it names (detect --action), otherwise the closest earlier
    # action on the same host inside the window. Crediting every earlier action would make one alert "see" everything.
    by_id = {a.get("id"): a for a in acts}
    credit = {a.get("id"): [] for a in acts}
    used = set()
    for i, b in enumerate(blue):
        named = by_id.get(b.get("action")) if b.get("action") else None
        if named is not None:
            credit[named.get("id")].append((max((b["t"] - parse_time(named["t"])).total_seconds(), 0), i, b)); used.add(i)
            continue
        cands = []
        for a in acts:
            dt_ = (b["t"] - parse_time(a["t"])).total_seconds()
            if 0 <= dt_ <= window_min * 60 and (_host_match(a["host"], b["host"]) or not b["host"]):
                cands.append((dt_, a))
        if cands:
            dt_, a = min(cands, key=lambda x: x[0])
            credit[a.get("id")].append((dt_, i, b)); used.add(i)
    rows = []
    for a in acts:
        hits = sorted(credit[a.get("id")], key=lambda x: x[0])
        lvl = max((h[2]["level"] for h in hits), default=None, key=lambda l: int(l[1:]) if l[1:].isdigit() else 0)
        price = pricing.lookup(a.get("class") or "")
        rows.append({"action": a.get("id"), "t": a["t"], "host": a.get("host"), "text": short(a.get("text", ""), 70), "class": a.get("class"),
                     "cost_estimate": price[0] if price else None, "seen": bool(hits), "first_after_s": int(hits[0][0]) if hits else None,
                     "level": lvl, "first_source": hits[0][2]["source"] if hits else None, "alerts": len(hits)})
    unmatched = [b for i, b in enumerate(blue) if i not in used]
    seen = [r for r in rows if r["seen"]]
    missed = [r for r in rows if not r["seen"]]
    rank = lambda r: (-(int(r["level"][1:]) if r["level"] and r["level"][1:].isdigit() else 0), r["first_after_s"] if r["first_after_s"] is not None else 10**9)
    top = sorted(seen, key=rank)[:3]
    lessons = []
    for r in top:
        base = f"{r['action']} ({short(r['text'], 50)}) was seen as {r['level']} after {r['first_after_s']}s via {r['first_source'] or 'an alert'}."
        if r["class"] and pricing.lookup(r["class"]):
            base += f" Class '{r['class']}' leaves: {pricing.lookup(r['class'])[1]}. Make this a standing rule: avoid it, replace it, or plan for it."
        else:
            base += " Decide whether this becomes a standing rule: avoid it, replace it, or plan for it."
        lessons.append(base)
    level_counts = {}
    for r in rows:
        level_counts[r["level"] or "none"] = level_counts.get(r["level"] or "none", 0) + 1
    return {"window_min": window_min, "actions": rows, "seen": len(seen), "missed": len(missed), "unmatched_blue": unmatched,
            "top_expensive": top, "lessons": lessons, "level_counts": level_counts, "levels": LEVELS}


def to_markdown(r) -> str:
    L = ["# Purple review", "", f"Each blue event is credited to one red action: the one it names, or else the closest earlier action on the same host within {r['window_min']} minutes. Actions with no host are not scored. All times UTC.", ""]
    n = len(r["actions"])
    L.append(f"{r['seen']} of {n} actions were seen by blue; {r['missed']} were not. Detection levels: " +
             (", ".join(f"{k}: {v}" for k, v in sorted(r["level_counts"].items())) or "-") + ".")
    L.append("\n## The three most expensive actions\n")
    for x in r["lessons"] or ["Nothing was seen."]:
        L.append(f"- {x}")
    L.append("\n## Not seen (replay these paths with blue)\n")
    for a in [x for x in r["actions"] if not x["seen"]] or []:
        L.append(f"- {a['t']} {a['host'] or '?'} {a['action']}: {a['text']}")
    if not r["missed"]:
        L.append("- none")
    L.append("\n## Blue events with no matching red action\n")
    L.append("These are either false positives, real activity by someone else, or red actions that were never logged. Each one needs an answer.\n")
    for b in r["unmatched_blue"]:
        L.append(f"- {iso(b['t'])} {b['host'] or '?'} {b['source']}: {short(b['summary'], 80)}")
    if not r["unmatched_blue"]:
        L.append("- none")
    L.append("\n## Full table\n")
    L.append("| Time | Host | Action | Class | Seen | After (s) | Level | First source |")
    L.append("|---|---|---|---|---|---|---|---|")
    for a in r["actions"]:
        L.append(f"| {a['t']} | {a['host'] or ''} | {a['action']} {a['text']} | {a['class'] or ''} | {'yes' if a['seen'] else 'no'} | {a['first_after_s'] if a['first_after_s'] is not None else ''} | {a['level'] or ''} | {a['first_source'] or ''} |")
    return "\n".join(L) + "\n"
