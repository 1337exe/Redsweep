"""Bring logs from the tools you already use into the journal. Imported rows keep their original time and are marked as imported."""
from __future__ import annotations

import csv
import datetime as dt
import json
import re
from pathlib import Path

from .util import UTC, iso, now, parse_time, sha256_text

# command word -> price-table class (best effort; edit the class afterwards if a guess is wrong)
GUESS = [
    (r"\b(logonpasswords|mimikatz|sekurlsa|lsadump|hashdump)\b", "lsass-access"),
    (r"\b(psexec|psexec64|jump\s+psexec|jump\s+winrm|scshell|sc\s+\\\\)", "remote-service-create"),
    (r"\bdcsync\b", "dcsync"),
    (r"\b(kerberoast|asktgs)\b", "bulk-kerberoast"),
    (r"\b(asktgt|klist|kerberos)\b", "kerberos-ticket-request"),
    (r"\b(inject|shinject|dllinject|process-inject|spawnto)\b", "process-injection"),
    (r"\b(execute-assembly|powerpick|powershell|psinject)\b", "powershell"),
    (r"\b(schtasks|at\s+\\\\)\b", "scheduled-task-create"),
    (r"\b(wmic|wmi)\b", "wmi-exec"),
    (r"\b(upload|cp\s|copy\s)\b", "write-to-disk"),
    (r"\b(ldapsearch|adfind|sharphound|bloodhound)\b", "bloodhound-full-collection"),
    (r"\bssh\b", "ssh-login"),
    (r"\bsudo\b", "sudo"),
    (r"\bcrontab\b", "cron-edit"),
    (r"authorized_keys", "authorized-keys-edit"),
    (r"\buseradd\b|\bnet\s+user\b", "user-add"),
]


def guess_class(text: str):
    for rx, cls in GUESS:
        if re.search(rx, text or "", re.I):
            return cls
    return None


class ImportError_(Exception):
    pass


def _rows_cobalt_strike(path, year, host):
    """beacon_*.log: `MM/DD HH:MM:SS UTC [input] <operator> command`. Only operator input and errors are read."""
    rx = re.compile(r"^(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d) UTC \[(input|error|checkin)\]\s*(?:<([^>]*)>\s*)?(.*)$")
    out = []
    host = host or Path(path).stem
    for line in Path(path).read_text(errors="replace").splitlines():
        m = rx.match(line)
        if not m:
            continue
        mo, dd, hh, mi, ss, kind, op, rest = m.groups()
        t = dt.datetime(year, int(mo), int(dd), int(hh), int(mi), int(ss), tzinfo=UTC)
        if kind == "input":
            out.append({"t": t, "host": host, "text": rest.strip(), "result": "ok", "orig_op": op or "", "tool": "cobalt-strike"})
        elif kind == "error" and out:
            out[-1]["result"] = "fail"
    return out


def parse_map(pairs):
    out = {}
    for p in pairs or []:
        k, sep, v = p.partition("=")
        if not sep or not k.strip() or not v.strip() or k.strip() not in ("time", "text", "host", "result", "class", "operator", "command", "tool"):
            raise ImportError_(f"--map needs NAME=COLUMN with NAME one of time, text, host, result, class, operator, command, tool (got {p!r})")
        out[k.strip()] = v.strip().lower()
    return out


def _rows_generic(path, mapping=None):
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig")
    rows = [json.loads(l) for l in text.splitlines() if l.strip()] if p.suffix.lower() in (".jsonl", ".ndjson") else list(csv.DictReader(text.splitlines()))
    out = []
    for i, r in enumerate(rows, 1):
        low = {str(k).lower().strip(): v for k, v in r.items()}
        for name, col in (mapping or {}).items():
            if col not in low:
                raise ImportError_(f"row {i}: mapped column {col!r} is not in the file (columns: {', '.join(sorted(low))})")
            low[name] = low[col]
        t = low.get("time") or low.get("timestamp") or low.get("start_date")
        cmd = low.get("command") or None
        txt = low.get("text") or low.get("description") or cmd
        if not t or not txt:
            raise ImportError_(f"row {i}: needs a time and a text/command column")
        out.append({"t": parse_time(t), "host": low.get("host") or low.get("dest_ip") or "", "text": txt,
                    "result": (low.get("result") or "ok"), "orig_op": low.get("operator") or low.get("operator_name") or "",
                    "tool": low.get("tool") or "", "class": low.get("class") or None, "cmd": cmd if cmd and cmd != txt else None})
    return out


FORMATS = {"cobalt-strike": "beacon_*.log from Cobalt Strike", "csv": "CSV with time,host,text[,result,class,operator]",
           "jsonl": "JSON lines with the same fields", "ghostwriter": "Ghostwriter operation-log CSV export"}


def parse(fmt, path, year=None, host=None, mapping=None):
    if not Path(path).is_file():
        raise ImportError_(f"{path}: not a file")
    if fmt == "cobalt-strike":
        return _rows_cobalt_strike(path, year or now().year, host)
    if fmt in ("csv", "jsonl", "ghostwriter"):
        return _rows_generic(path, mapping)
    raise ImportError_(f"format must be one of {sorted(FORMATS)}")


def do_import(eng, fmt, path, year=None, host=None, dry_run=False, mapping=None):
    """-> (added, skipped). Rows already imported (same time, host, text) are skipped, so re-importing a growing log is safe."""
    rows = parse(fmt, path, year, host, mapping)
    st = eng.state()
    have = {a.get("import_key") for a in st.actions if a.get("import_key")}
    added = skipped = 0
    src = sha256_text(Path(path).read_text(errors="replace"))
    for r in rows:
        key = sha256_text(f"{iso(r['t'])}|{r['host']}|{r['text']}")[:16]
        if key in have:
            skipped += 1
            continue
        if not dry_run:
            eng.log_action(r["text"], host=r["host"] or None, result=r["result"] if r["result"] in ("ok", "fail", "partial") else "ok",
                           cls=r.get("class") or guess_class(r["text"]), at=iso(r["t"]), imported=True, import_key=key, cmd=r.get("cmd"),
                           tags=[x for x in [f"orig_op:{r['orig_op']}" if r["orig_op"] else "", f"tool:{r['tool']}" if r["tool"] else ""] if x])
        have.add(key)
        added += 1
    if not dry_run:
        eng._ap("import", {"format": fmt, "file": Path(path).name, "sha256": src, "added": added, "skipped": skipped}, eng.op)
    return added, skipped
