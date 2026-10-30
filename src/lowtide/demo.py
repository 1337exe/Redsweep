"""A made-up engagement (HARBOR, a fictional credit union) so you can read a finished record before you start your own.
Everything here is invented. It runs no commands and touches nothing outside its folder."""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import shutil
from pathlib import Path

from .control import build_sitrep
from .ops import Engagement
from .store import Store
from .util import UTC, iso

BASE = dt.datetime(2026, 9, 14, 0, 0, tzinfo=UTC)
SCOPE = {
    "engagement": "HARBOR (fictional)",
    "window": {"start": "2026-09-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
    "in_scope": {"hosts": ["*.brightwater.example", "10.40.0.0/16"], "cloud_projects": ["bw-claims-dev"], "accounts": []},
    "out_of_scope": ["*.mdr-vendor.example", "10.40.250.0/24"],
    "forbidden_actions": ["payment-approval-click", "denial-of-service", "real-data-exfil"],
    "roles": {"control_team": ["pat", "robin"], "red_lead": ["alex"]},
    "tripwires": ["external_party", "production_containment", "exec_crisis"],
}


def at(day, hh=0, mm=0):
    return BASE + dt.timedelta(days=day, hours=hh, minutes=mm)


def build_demo(directory, finish=False, quiet=False):
    home = Path(directory) / ".lowtide"
    if home.exists():
        shutil.rmtree(home)
    store = Store(home)
    store.init("HARBOR", "Brightwater Credit Union (fictional)", "alex")
    store.scope_path.write_text(json.dumps(SCOPE, indent=2) + "\n")
    store.config_path.write_text(json.dumps({"name": "HARBOR", "client": "Brightwater Credit Union (fictional)", "default_operator": "alex"}, indent=2) + "\n")
    alex, sam, pat = (Engagement(store, o) for o in ("alex", "sam", "pat"))

    def at_(e, *t):
        e.clock = at(*t)
        return e

    at_(pat, 0, 1).note("kick-off: the Control Team is pat and robin; their channel is not on client infrastructure")
    # day 1
    at_(alex, 1, 1, 5).log_action("read the test brief; confirmed the two flags with the Control Team", result="ok")
    at_(alex, 1, 2, 10).log_action("listed shared folders on the file server", host="fs01.brightwater.example", cls="smb-admin-share-write", layer="network-path")
    at_(alex, 1, 2, 40).log_action("tried the provided test account on the claims app", host="claims.brightwater.example", result="fail", layer="authentication",
                                   assumption="the test account has the analyst role")
    ev_a, _ = at_(alex, 1, 3, 5).log_action("tried it again with the role name from the brief", host="claims.brightwater.example", result="fail", layer="authorization",
                                          assumption="the test account has the analyst role")
    c1 = at_(alex, 1, 3, 30).add_change("config", "claims.brightwater.example", "app setting export_limit", "raised from 100 to 5000 for the test",
                                      original="export_limit=100", rollback_plan="set it back to 100", ignore=[r"^#"])
    c2 = at_(alex, 1, 4, 0).add_change("account", "dir01.brightwater.example", "user harbor-test-1", "created a test user in the lab group", created=True,
                                     rollback_plan="delete the user")
    c3 = at_(alex, 1, 4, 20).add_change("infra", "xfer1.brightwater.example", "test web server for file transfer", "started the server", created=True, autonomous=True,
                                      rollback_plan="stop the server and delete its files")
    k1 = at_(alex, 1, 5, 0).add_cred("password", "svc-claims-etl", label="found in a script on the file share", material="not-a-real-password",
                                   location="operator notes only", host="fs01.brightwater.example", issued_latest=iso(at(1, 5, 0)))
    # day 2
    at_(sam, 2, 1, 0).log_action("read the claims schema (names and counts only)", host="claims.brightwater.example", cls="gcp-asset-search")
    f = Path(directory) / "canary-proof.txt"
    f.write_text('{"canary": "LT-demo0001"}\n')
    at_(sam, 2, 2, 0).add_evidence(str(f), "canary read from the claims table", ladder="canary", host="claims.brightwater.example")
    at_(sam, 2, 2, 30).log_action("read the synthetic canary record by its key", host="claims.brightwater.example", result="ok")
    # day 3: blue notices
    at_(alex, 3, 0, 40).log_action("listed shared folders on the file server a second time, from a new account", host="fs01.brightwater.example",
                                   cls="smb-admin-share-write", layer="network-path")
    at_(alex, 3, 0, 52).detect("L1", host="fs01.brightwater.example", source="EDR", evidence="alert on the file server, not triaged")
    at_(alex, 3, 1, 40).detect("L3", host="fs01.brightwater.example", source="SOC", evidence="incident opened; analyst contacted the server owner")
    at_(alex, 3, 1, 45).freeze("SOC opened an incident on fs01; stopping all operator activity")
    at_(alex, 3, 2, 10).log_action("checked that our test server and operator notes are healthy (no target contact)", result="ok", layer="tooling")
    stt = alex.state()
    based = [stt.actions[-1]["id"]]
    ev, d = build_sitrep(at_(alex, 3, 2, 20), "frozen, test server still running", "SOC incident on fs01 opened 01:40 UTC after an EDR alert at 00:52 UTC",
                         "the SOC has our file-server activity; nothing shows they have the test user or the config change",
                         "decide: continue, go dark, or end the scenario", "client sees real response activity, not a test", based_on=based)
    at_(alex, 3, 2, 30).recommend("go-dark", "keep the test server asleep and wait; do not touch the file server again", options=["suspend"])
    dec = at_(pat, 3, 3, 0).decide("go-dark", "pat", "the SOC response is useful to measure; no new red activity until day 5", tags=["production_containment"],
                                 recommended_by="alex")
    at_(pat, 5, 1, 0).resume("pat", dec["id"])
    # day 6: cleanup
    at_(alex, 6, 1, 0).log_action("resumed; started cleanup in ledger order", result="ok")
    at_(alex, 6, 1, 10).rollback(c1["id"], how="set export_limit back to 100 in the app settings")
    at_(sam, 6, 1, 20).verify(c1["id"], readback_value="export_limit=100")
    at_(alex, 6, 1, 30).rollback(c3["id"], how="stopped the test server and deleted its files", durable=None)
    at_(sam, 6, 1, 40).verify(c3["id"], attest=True, note="checked the host: port closed, directory removed")
    at_(alex, 6, 1, 45).cred_step(k1["id"], 1, "removed from operator notes")
    if finish:
        at_(alex, 6, 2, 0).rollback(c2["id"], how="deleted harbor-test-1")
        at_(sam, 6, 2, 10).verify(c2["id"], readback_value="<absent>")
        at_(alex, 6, 2, 15).cred_step(k1["id"], 2, "added to the client rotation list")
        e1 = next(iter(alex.state().evidence))
        at_(alex, 6, 2, 30).handoff(e1, "pat", "kept by the Control Team for the report")
    # the blue timeline the client sent for the joint review
    with open(Path(directory) / "blue-timeline.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["time", "host", "source", "summary", "level"])
        w.writerow([iso(at(3, 0, 52)), "fs01.brightwater.example", "EDR", "unusual remote file listing", "L1"])
        w.writerow([iso(at(3, 1, 40)), "fs01.brightwater.example", "SOC", "incident opened", "L3"])
        w.writerow([iso(at(4, 2, 0)), "wks-077.brightwater.example", "mail gateway", "unrelated phishing report", "L1"])
    if not quiet:
        print(f"demo engagement written to {Path(directory).resolve()}")
        print("Look around (run from that folder, or set LOWTIDE_HOME):")
        print(f"  cd {Path(directory).resolve()}")
        print((f"  $env:LOWTIDE_HOME = '{home.resolve()}'   # PowerShell" if os.name == "nt" else f"  export LOWTIDE_HOME={home.resolve()}"))
        print("  lowtide status")
        print("  lowtide change list")
        print("  lowtide close --check" + ("" if finish else "          # fails: three things were never cleaned up"))
        print("  lowtide sitrep --show 1")
        print("  lowtide review blue-timeline.csv")
        if finish:
            print("The cleanup is already done; try: lowtide close")
        else:
            print("Then finish the cleanup yourself:")
            print("  lowtide demo --finish   (does it for you), then: lowtide close")
    return 0
