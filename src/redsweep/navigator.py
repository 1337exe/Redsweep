"""An ATT&CK Navigator layer: every technique you used, coloured by how far the blue team got with it."""
from __future__ import annotations

import json

from . import pricing


def layer(review_result: dict, name="Redsweep engagement") -> dict:
    by = {}
    for a in review_result["actions"]:
        tid = pricing.TECHNIQUES.get(a.get("class") or "")
        if not tid:
            continue
        lvl = int(a["level"][1:]) + 1 if a.get("level") and a["level"][1:].isdigit() else 0  # 0 = not seen, 1 = L0 ... 6 = L5
        t = by.setdefault(tid, {"techniqueID": tid, "score": 0, "comment": "", "actions": []})
        t["score"] = max(t["score"], lvl)
        t["actions"].append(f"{a['action']} {a['text']} -> " + (a["level"] if a.get("level") else "not seen"))
    techs = []
    for t in by.values():
        techs.append({"techniqueID": t["techniqueID"], "score": t["score"], "comment": "\n".join(t["actions"]), "enabled": True})
    return {"name": name, "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"}, "domain": "enterprise-attack",
            "description": "Score 0 = used and not seen by blue. 1 = L0 (telemetry existed, nobody looked) up to 6 = L5 (escalated out of security).",
            "gradient": {"colors": ["#ffffff", "#9ad1c0", "#f2c14e", "#e0623b", "#a1262b"], "minValue": 0, "maxValue": 6},
            "techniques": techs, "legendItems": [{"label": "0 not seen", "color": "#ffffff"}, {"label": "6 escalated (L5)", "color": "#a1262b"}]}


def dumps(l) -> str:
    return json.dumps(l, indent=2)
