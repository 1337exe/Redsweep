"""Write the operator log out for other tools."""
from __future__ import annotations

import csv
import io
import json

GW_COLS = ["start_date", "end_date", "source_ip", "dest_ip", "tool", "user_context", "command", "description", "output", "comments", "operator_name"]


def export(st, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(st.actions, indent=2, default=str)
    if fmt == "markdown":
        lines = ["| Time (UTC) | Operator | Host | Result | Action |", "|---|---|---|---|---|"]
        for a in st.actions:
            lines.append(f"| {a['t']} | {a['op']} | {a.get('host') or ''} | {a.get('result', 'ok')} | {a['text'].replace('|', '/')} |")
        return "\n".join(lines) + "\n"
    if fmt == "ghostwriter":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=GW_COLS)
        w.writeheader()
        for a in st.actions:
            w.writerow({"start_date": a["t"].replace("T", " ").rstrip("Z"), "end_date": a["t"].replace("T", " ").rstrip("Z"), "source_ip": "",
                        "dest_ip": a.get("host") or "", "tool": a.get("class") or "", "user_context": "", "command": a.get("cmd") or a["text"],
                        "description": a["text"] if a.get("cmd") else "", "output": f"sha256:{a['out_sha']}" if a.get("out_sha") else "",
                        "comments": f"result={a.get('result', 'ok')} layer={a.get('layer', 'n/a')}" + (f" assumption={a['assumption']}" if a.get("assumption") else ""),
                        "operator_name": a["op"]})
        return buf.getvalue()
    raise ValueError("format must be ghostwriter, json or markdown")
