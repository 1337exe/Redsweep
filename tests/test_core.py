import json
import sys
import os
import shutil
import subprocess
import tempfile
import threading
import zipfile
import pytest

needs_gpg = pytest.mark.skipif(not shutil.which('gpg') or os.name == 'nt', reason='gpg not installed (or Windows, where gpg signing is untested)')

from redsweep import importers, pricing, review, seal
from redsweep.cli import main
from redsweep.closeout import blockers, check, report_data, to_html, to_markdown
from redsweep.control import build_sitrep
from redsweep.ops import OpsError, normalize
from redsweep.scope import Scope, host_of
from redsweep.store import Store, StoreError


# ---------- store
def test_chain_detects_edit(eng):
    eng.note("a"); eng.note("b")
    p = eng.store.files()[0]
    p.write_text(p.read_text().replace('"b"', '"c"'))
    assert not eng.store.verify()[0][1]


def test_chain_detects_deleted_line(eng):
    for i in range(4):
        eng.note(str(i))
    p = eng.store.files()[0]
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not eng.store.verify()[0][1]


def test_concurrent_appends_keep_chain_valid(eng):
    def w(n):
        for i in range(15):
            eng.note(f"{n}-{i}")
    ts = [threading.Thread(target=w, args=(n,)) for n in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]
    ok, n, _ = eng.store.verify()[0][1:]
    assert ok and n == 61  # init + 60


def test_operator_name_validated(home):
    st = Store(home)
    with pytest.raises(StoreError):
        st.operator("../evil")


def test_unknown_config_key_rejected(eng):
    c = json.loads(eng.store.config_path.read_text()); c["strict_scoop"] = True
    eng.store.config_path.write_text(json.dumps(c))
    with pytest.raises(StoreError):
        eng.store.cfg()


def test_two_operators_merge_in_time_order(mk):
    a = mk("alice"); b = mk("bob")
    a.clock = "2026-01-02T10:00:00Z"; b.clock = "2026-01-02T09:00:00Z"
    a.note("second"); b.note("first")
    st = a.state()
    assert [n["text"] for n in st.notes] == ["first", "second"]


# ---------- scope
def test_scope_cidr_url_and_precedence():
    s = Scope({"in_scope": {"hosts": ["10.0.0.0/8", "*.a.example"]}, "out_of_scope": ["10.1.0.0/16", "x.a.example"]})
    assert s.check("10.2.3.4")[0] == "in"
    assert s.check("10.1.2.3")[0] == "out"          # out beats in
    assert s.check("https://x.a.example:8443/path")[0] == "out"
    assert s.check("y.a.example")[0] == "in"
    assert s.check("evil.example")[0] == "unlisted"
    assert host_of("https://x.a.example:8443/p") == "x.a.example" and host_of("10.1.2.3:22") == "10.1.2.3"


def test_window_enforced(mk):
    e = mk(scope={**__import__("conftest").SCOPE, "window": {"start": "2020-01-01T00:00:00Z", "end": "2020-02-01T00:00:00Z"}})
    with pytest.raises(OpsError, match="window"):
        e.log_action("x", host="a.lab.example")


def test_forbidden_action(eng):
    with pytest.raises(OpsError, match="forbidden"):
        eng.log_action("x", host="a.lab.example", cls="denial-of-service")


def test_override_is_recorded_and_reported(eng):
    eng.log_action("x", host="other.example", override="pat approved by phone 10:02")
    st = eng.state()
    assert st.overrides and "pat approved" in st.overrides[0]["reason"]
    assert any(i["area"] == "scope" for i in check(eng))


# ---------- ledger
def test_original_required(eng):
    with pytest.raises(OpsError, match="original"):
        eng.add_change("config", "a.lab.example", "o", "c")


def _cat(path):
    return f'"{sys.executable}" -c "import sys;sys.stdout.write(open(sys.argv[1]).read())" "{path}"'


def test_capture_roundtrip_and_ignore_regex(eng, tmp_path):
    f = tmp_path / "c.ini"; f.write_text("a=1\n# saved 10:01\n")
    c = eng.add_change("config", "127.0.0.1", "c", "x", capture=_cat(f), ignore=[r"^# saved"])
    f.write_text("a=2\n# saved 10:05\n")
    eng.rollback(c["id"], how="reverted")
    f.write_text("a=1\n# saved 11:30\n")  # only the ignored line differs
    assert eng.verify(c["id"])["result"] == "match"


def test_absent_object_roundtrip(eng, tmp_path):
    f = tmp_path / "new.txt"
    probe = f'"{sys.executable}" -c "import os,sys;print(open(sys.argv[1]).read() if os.path.exists(sys.argv[1]) else 0)" "{f}"'
    c = eng.add_change("file", "127.0.0.1", str(f), "create", capture=probe, created=False)
    f.write_text("x")
    eng.rollback(c["id"], how="rm"); f.unlink()
    assert eng.verify(c["id"])["result"] == "match"


def test_verify_before_rollback_refused(eng):
    c = eng.add_change("config", "127.0.0.1", "o", "c", original="v")
    with pytest.raises(OpsError, match="not been rolled back"):
        eng.verify(c["id"], readback_value="v")


def test_verify_mismatch_blocks_close(eng):
    c = eng.add_change("config", "127.0.0.1", "o", "c", original="v")
    eng.rollback(c["id"], how="x")
    assert eng.verify(c["id"], readback_value="other")["result"] == "mismatch"
    assert any("does not match" in b["msg"] for b in blockers(check(eng)))


def test_attest_needs_note_and_warns(eng):
    c = eng.add_change("config", "127.0.0.1", "o", "c", original="v")
    eng.rollback(c["id"], how="x")
    with pytest.raises(OpsError, match="note"):
        eng.verify(c["id"], attest=True)
    eng.verify(c["id"], attest=True, note="looked at the host")
    items = check(eng)
    assert not blockers(items) or all("ledger" != b["area"] for b in blockers(items))
    assert any("attestation" in i["msg"] for i in items)


def test_min_strength_enforced(mk):
    e = mk(cfg={"min_verify_strength": "manual"})
    c = e.add_change("config", "127.0.0.1", "o", "c", original="v")
    e.rollback(c["id"], how="x")
    with pytest.raises(OpsError, match="at least"):
        e.verify(c["id"], attest=True, note="n")


def test_second_operator_required(mk, home):
    a = mk("alice", cfg={"require_second_operator": True}); b = mk("bob")
    c = a.add_change("config", "127.0.0.1", "o", "c", original="v")
    a.rollback(c["id"], how="x")
    with pytest.raises(OpsError, match="second operator"):
        a.verify(c["id"], readback_value="v")
    b.cfg = a.cfg
    assert b.verify(c["id"], readback_value="v")["result"] == "match"


def test_waiver_needs_reason_and_by(eng):
    c = eng.add_change("config", "127.0.0.1", "o", "c", original="v")
    with pytest.raises(OpsError):
        eng.waive(c["id"], "", "pat")
    eng.waive(c["id"], "client keeps it", "pat")
    assert not [b for b in blockers(check(eng)) if b["area"] == "ledger"]


def test_durable_control_reported(eng):
    c = eng.add_change("iam", "127.0.0.1", "role X", "add permission", original="p1")
    eng.rollback(c["id"], how="restored", durable="analyst still holds iam.roles.update")
    eng.verify(c["id"], readback_value="p1")
    assert any("durable control" in i["msg"] for i in check(eng))


def test_secret_never_in_journal(eng):
    eng.add_change("config", "127.0.0.1", "k", "c", original="password = hunter2hunter2")
    assert "hunter2hunter2" not in eng.store.files()[0].read_text()


def test_unique_prefix_lookup(eng):
    c = eng.add_change("config", "127.0.0.1", "o", "c", original="v")
    eng.rollback(c["id"][:4], how="x")
    with pytest.raises(OpsError):
        eng.rollback("zz", how="x")


# ---------- credentials, evidence
def test_cred_window_math_and_waiver(eng):
    k = eng.add_cred("gcp-access-token", "svc", material="x", issued_latest="2026-01-01T00:00:00Z")
    c = eng.state().creds[k["id"]]
    assert c["window_end"] == "2026-01-01T01:00:00Z"
    for i in range(1, len(c["steps"]) + 1):
        eng.cred_step(k["id"], i)
    st = eng.state()
    assert st.cred_status(st.creds[k["id"]])[0] == "confirmed"  # window long past


def test_cred_open_window_blocks_then_accepted(eng):
    k = eng.add_cred("gcp-access-token", "svc", material="x")
    for i in range(1, 3):
        eng.cred_step(k["id"], i)
    assert any(b["area"] == "credentials" for b in blockers(check(eng)))
    eng.cred_window(k["id"], "client accepts 60 minutes", "pat")
    assert not any(b["area"] == "credentials" for b in blockers(check(eng)))


def test_cred_material_never_stored(eng):
    eng.add_cred("password", "svc", material="correct-horse-battery")
    assert "correct-horse" not in eng.store.files()[0].read_text()


def test_real_record_needs_control_team(eng, tmp_path):
    f = tmp_path / "r.txt"; f.write_text("x")
    with pytest.raises(OpsError):
        eng.add_evidence(str(f), "rec", ladder="real-record")
    with pytest.raises(OpsError):
        eng.add_evidence(str(f), "rec", ladder="real-record", approved_by="alice")
    eng.add_evidence(str(f), "rec", ladder="real-record", approved_by="pat")


def test_evidence_destroy_hashes_then_deletes(eng, tmp_path):
    f = tmp_path / "e.txt"; f.write_text("secret data")
    e = eng.add_evidence(str(f), "x")
    eng.destroy(e["id"], "overwrite and delete", "pat", delete=True)
    assert not f.exists()
    assert eng.state().evidence[e["id"]]["destroyed"]["sha256_before"] == e["data"]["sha256"]


def test_canary(eng, tmp_path):
    rec, digest = eng.canary_make("c")
    assert eng.canary_check(json.dumps(rec), digest)[0]
    assert not eng.canary_check(json.dumps({"canary": "other"}), digest)[0]


# ---------- control team
def test_freeze_blocks_target_activity_but_allows_notes(eng):
    eng.freeze("x")
    with pytest.raises(OpsError, match="FROZEN"):
        eng.log_action("x", host="a.lab.example")
    eng.log_action("checked our own server", result="ok")
    c = eng.state()
    assert c.frozen


def test_stop_needs_decision_to_resume(eng):
    eng.freeze("intruder?", condition="other-intruder")
    with pytest.raises(OpsError, match="decision"):
        eng.resume("pat")
    d = eng.decide("suspend", "pat", "stop the test")
    eng.resume("pat", d["id"])
    assert not eng.state().frozen


def test_tripwire_requires_matching_decision(eng):
    with pytest.raises(OpsError, match="Control Team must decide"):
        eng.log_action("call the MDR", host="a.lab.example", tripwire="external_party")
    d = eng.decide("continue", "pat", "approved", tags=["external_party"])
    eng.log_action("call the MDR", host="a.lab.example", tripwire="external_party", decision=d["id"])


def test_sitrep_requires_log_and_fields(eng):
    with pytest.raises(OpsError, match="operator log"):
        build_sitrep(eng, "s", "obs", ask="what now")
    a, _ = eng.log_action("did a thing", host="a.lab.example")
    with pytest.raises(OpsError, match="observed"):
        build_sitrep(eng, "s", "", ask="x", based_on=[a["id"]])
    ev, d = build_sitrep(eng, "s", "obs", ask="what now", based_on=[a["id"]])
    assert d["n"] == 1 and a["id"] in d["based_on"]


def test_sitrep_autonomous_comes_from_ledger(eng):
    eng.add_change("implant", "a.lab.example", "agent on host", "installed", created=True)
    eng.add_change("config", "a.lab.example", "setting", "x", original="1")
    a, _ = eng.log_action("x", host="a.lab.example")
    ev, d = build_sitrep(eng, "s", "obs", ask="a", based_on=[a["id"]])
    assert len(d["autonomous"]) == 1 and "agent" in d["autonomous"][0]


def test_repeat_assumption_warning(eng):
    for _ in range(2):
        eng.log_action("t", host="a.lab.example", result="fail", assumption="svc has SPN")
    assert eng.state().warnings
    eng.log_action("t", host="a.lab.example", result="fail", assumption="other one", new_info=True)
    assert len(eng.state().warnings) == 1


def test_all_success_log_is_flagged(eng):
    for i in range(10):
        eng.log_action(f"a{i}", host="a.lab.example")
    assert any("not one failure" in i["msg"] for i in check(eng))


def test_teardown_order(eng):
    eng.add_change("infra", "a.lab.example", "server", "x", created=True)
    eng.add_change("implant", "a.lab.example", "agent", "x", created=True)
    eng.add_change("config", "a.lab.example", "cfg", "x", original="1")
    kinds = [s["area"] for s in eng.teardown_plan()]
    assert kinds.index("implant") < kinds.index("config") < kinds.index("infra")


# ---------- price table
def test_price_lookup():
    assert pricing.lookup("lsass-access")[0] == "high"
    assert "not in the price table" in pricing.explain("nope")
    assert len(pricing.PRICES) >= 30


# ---------- importers and exporters
def test_cobalt_strike_import(eng):
    a, s = importers.do_import(eng, "cobalt-strike", "examples/beacon_demo.log", 2026, "127.0.0.1")
    assert a == 5 and s == 0
    acts = eng.state().actions
    assert any(x["result"] == "fail" and "hostname" in x["text"] for x in acts)
    assert any(t.startswith("orig_op:bob") for x in acts for t in x.get("tags", []))


def test_import_time_is_original_and_utc(eng):
    importers.do_import(eng, "cobalt-strike", "examples/beacon_demo.log", 2026, "127.0.0.1")
    assert eng.state().actions[0]["t"] == "2026-10-03T09:12:44Z"


def test_ghostwriter_roundtrip(eng):
    importers.do_import(eng, "ghostwriter", "examples/ghostwriter-oplog.csv")
    from redsweep.exporters import export
    csv_text = export(eng.state(), "ghostwriter")
    assert csv_text.splitlines()[0].startswith("start_date,end_date")
    assert "checked the status page" in csv_text


def test_bad_import_row_is_an_error(eng, tmp_path):
    f = tmp_path / "x.csv"; f.write_text("time,host\n2026-01-01,a\n")
    with pytest.raises(importers.ImportError_):
        importers.do_import(eng, "csv", str(f))


def test_import_scope_not_enforced_for_history(eng, tmp_path):
    f = tmp_path / "x.csv"; f.write_text("time,host,text\n2026-01-01T00:00:00Z,somewhere.else.example,did a thing\n")
    assert importers.do_import(eng, "csv", str(f)) == (1, 0)


# ---------- review
def test_review_join_and_unmatched(eng):
    eng.log_action("listed shares", host="ws1.lab.example", cls="smb-admin-share-write", at="2026-10-03T10:00:00Z")
    eng.log_action("quiet read", host="ws1.lab.example", at="2026-10-03T12:00:00Z")
    blue = [{"t": __import__("redsweep.util", fromlist=["x"]).parse_time("2026-10-03T10:07:00Z"), "host": "ws1", "source": "EDR", "summary": "s", "level": "L3", "ref": ""},
            {"t": __import__("redsweep.util", fromlist=["x"]).parse_time("2026-10-03T20:00:00Z"), "host": "ws9", "source": "SIEM", "summary": "n", "level": "L1", "ref": ""}]
    r = review.review(eng.state(), blue, 30)
    assert r["seen"] == 1 and r["missed"] == 1 and len(r["unmatched_blue"]) == 1
    assert r["actions"][0]["level"] == "L3" and "smb-admin-share-write" in r["lessons"][0]
    assert "Blue events with no matching red action" in review.to_markdown(r)


def test_review_bad_blue_file(tmp_path):
    f = tmp_path / "b.csv"; f.write_text("host,summary\na,b\n")
    with pytest.raises(review.ReviewError):
        review.load_blue(f)


# ---------- reports and packs
def test_report_escapes_html(eng):
    eng.add_change("config", "127.0.0.1", "<script>alert(1)</script>", "x", original="<img src=x onerror=alert(1)>")
    html = to_html(report_data(eng))
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    assert "default-src 'none'" in html


def test_markdown_report_clean_vs_not(eng):
    c = eng.add_change("config", "127.0.0.1", "o", "c", original="v")
    assert "NOT CLEAN" in to_markdown(report_data(eng))
    eng.rollback(c["id"], how="x"); eng.verify(c["id"], readback_value="v")
    eng.log_action("something failed", host="a.lab.example", result="fail")
    assert "CLEAN. Everything" in to_markdown(report_data(eng))


def test_pack_zip_slip_rejected(tmp_path):
    p = tmp_path / "evil.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("../evil.txt", "x"); z.writestr("MANIFEST.sha256", "")
    ok, msgs = seal.verify_pack(str(p))
    assert not ok and "unsafe" in msgs[0]


def test_pack_missing_manifest(tmp_path):
    p = tmp_path / "x.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "x")
    assert not seal.verify_pack(str(p))[0]


def test_hmac_seal_detects_wrong_key(eng, tmp_path):
    eng.note("x")
    kf = tmp_path / "k"; kf.write_bytes(b"key-one")
    body = seal.make_seal(eng.store, {"r": "x"}, str(kf))
    assert seal.check_seal(body, str(kf)) == "signature OK"
    kf2 = tmp_path / "k2"; kf2.write_bytes(b"key-two")
    assert "DOES NOT MATCH" in seal.check_seal(body, str(kf2))


def test_normalize():
    assert normalize("a  \nb\n\n\n") == "a\nb"
    assert normalize("a\n#x\nb", ["^#"]) == "a\nb"


# ---------- cli exit codes
def test_cli_codes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("REDSWEEP_HOME", str(tmp_path / "h")); monkeypatch.setenv("REDSWEEP_OPERATOR", "alice")
    assert main(["init", "--name", "X"]) == 0
    (tmp_path / "h" / "scope.json").write_text(json.dumps({"in_scope": {"hosts": ["127.0.0.1"]}}))
    assert main(["scope", "check", "evil.example"]) == 1
    assert main(["change", "add", "--kind", "file", "--host", "127.0.0.1", "--object", "o", "--change", "c", "--original", "v"]) == 0
    assert main(["close", "--check"]) == 2
    assert main(["verify"]) == 0
    assert main(["change", "list", "--open"]) == 0


def test_cli_mcp_no_exec(eng):
    from redsweep import mcp
    eng.allow_exec = False
    r = mcp.handle(eng, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "redsweep_change_add",
                         "arguments": {"kind": "file", "host": "127.0.0.1", "object": "o", "change": "c", "original_value": "v"}}})
    assert not r["result"].get("isError")
    names = {t["name"] for t in mcp.handle(eng, {"jsonrpc": "2.0", "id": 4, "method": "tools/list"})["result"]["tools"]}
    assert not any(n in names for n in ("redsweep_waive", "redsweep_decide", "redsweep_resume"))


# ---------- navigator and handoff
def test_navigator_layer(eng):
    from redsweep import navigator
    eng.log_action("dump", host="ws1.lab.example", cls="lsass-access", at="2026-10-03T10:00:00Z")
    eng.log_action("quiet", host="ws1.lab.example", cls="wmi-exec", at="2026-10-03T11:00:00Z")
    blue = [{"t": __import__("redsweep.util", fromlist=["x"]).parse_time("2026-10-03T10:03:00Z"), "host": "ws1", "source": "EDR", "summary": "", "level": "L4", "ref": ""}]
    lay = navigator.layer(review.review(eng.state(), blue))
    scores = {t["techniqueID"]: t["score"] for t in lay["techniques"]}
    assert scores == {"T1003.001": 5, "T1047": 0}


def test_handoff_lists_credentials_and_durable(eng):
    from redsweep import handoff
    eng.add_cred("gcp-sa-key", "svc@proj", material="k")
    c = eng.add_change("iam", "127.0.0.1", "role", "x", original="p")
    eng.rollback(c["id"], how="x", durable="analyst keeps iam.roles.update")
    t = handoff.build(eng.state())
    assert "svc@proj" in t and "disable then delete the key" in t and "iam.roles.update" in t


def test_review_ignores_actions_with_no_host(eng):
    eng.log_action("planning note, no target", result="ok", at="2026-10-03T10:00:00Z")
    r = review.review(eng.state(), [], 30)
    assert r["actions"] == [] and r["missed"] == 0


# ---------- import column mapping
def test_import_with_column_map(eng, tmp_path):
    f = tmp_path / "x.csv"
    f.write_text("ts,cmd_line,target,status\n2026-10-03T10:00:00Z,whoami,127.0.0.1,ok\n2026-10-03T10:01:00Z,id,127.0.0.1,fail\n")
    m = importers.parse_map(["time=ts", "text=cmd_line", "host=target", "result=status"])
    assert importers.do_import(eng, "csv", str(f), mapping=m) == (2, 0)
    acts = eng.state().actions
    assert [a["result"] for a in acts] == ["ok", "fail"] and acts[0]["host"] == "127.0.0.1"


def test_import_map_errors(eng, tmp_path):
    with pytest.raises(importers.ImportError_):
        importers.parse_map(["bogus=x"])
    with pytest.raises(importers.ImportError_):
        importers.parse_map(["time"])
    f = tmp_path / "x.csv"; f.write_text("a,b\n1,2\n")
    with pytest.raises(importers.ImportError_, match="not in the file"):
        importers.do_import(eng, "csv", str(f), mapping={"time": "nope"})


# ---------- gpg signing
@needs_gpg
def test_gpg_signed_pack_roundtrip_and_tamper(eng, tmp_path):
    gh = tempfile.mkdtemp(prefix="g", dir="/tmp" if os.path.isdir("/tmp") else None)  # a short path keeps gpg-agent sockets valid
    env = dict(os.environ, GNUPGHOME=gh)
    os.chmod(gh, 0o700)
    subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key", "lt@example.com", "default", "default", "never"], env=env, capture_output=True, check=True)
    old = os.environ.get("GNUPGHOME"); os.environ["GNUPGHOME"] = gh
    try:
        eng.note("x")
        body = seal.make_seal(eng.store, {"closeout.md": "x"})
        sp = tmp_path / "seal.json"; sp.write_text(seal.dump(body))
        asc = seal.gpg_sign(str(sp), "lt@example.com")
        pk = tmp_path / "p.zip"
        seal.build_pack(eng.store, str(pk), {"closeout.md": "x"}, body, {"seal.json.asc": open(asc, "rb").read()})
        ok, msgs = seal.verify_pack(str(pk))
        assert ok and any("gpg:" in m and "Good signature" in m for m in msgs)
        # forge: change the seal AND fix the manifest so only the signature can catch it
        import hashlib
        forged = tmp_path / "f.zip"
        with zipfile.ZipFile(pk) as zi, zipfile.ZipFile(forged, "w") as zo:
            files = {n: zi.read(n) for n in zi.namelist() if n != "MANIFEST.sha256"}
            files["seal.json"] = files["seal.json"].replace(b"closeout.md", b"closeout.xx")
            for n, d in files.items():
                zo.writestr(n, d)
            zo.writestr("MANIFEST.sha256", "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(files.items())))
        ok2, msgs2 = seal.verify_pack(str(forged))
        assert not ok2 and any("BAD signature" in m or "verification failed" in m for m in msgs2)
    finally:
        if old is None: os.environ.pop("GNUPGHOME", None)
        else: os.environ["GNUPGHOME"] = old
        shutil.rmtree(gh, ignore_errors=True)


# ---------- found by the local drill
def test_review_credits_each_blue_event_to_one_action(eng):
    from redsweep.util import parse_time
    eng.log_action("first", host="a.lab.example", at="2026-10-03T10:00:00Z")
    eng.log_action("second", host="a.lab.example", at="2026-10-03T10:05:00Z")
    blue = [{"t": parse_time("2026-10-03T10:06:00Z"), "host": "a", "source": "EDR", "summary": "s", "level": "L2", "ref": ""}]
    r = review.review(eng.state(), blue, 30)
    assert [x["seen"] for x in r["actions"]] == [False, True]  # the closest earlier action gets the credit, not both


def test_review_named_action_gets_the_credit(eng):
    a1, _ = eng.log_action("first", host="a.lab.example", at="2026-10-03T10:00:00Z")
    eng.log_action("second", host="a.lab.example", at="2026-10-03T10:05:00Z")
    eng.detect("L3", host="a.lab.example", source="lead", at="2026-10-03T10:06:00Z", action=a1["id"])
    r = review.review(eng.state(), [], 30)
    assert [x["seen"] for x in r["actions"]] == [True, False]


def test_wrap_stamps_the_start_time(tmp_path, monkeypatch):
    import json as _j
    from redsweep import cli
    from redsweep.store import Store
    home = tmp_path / ".lt"
    monkeypatch.setenv("REDSWEEP_HOME", str(home)); monkeypatch.setenv("REDSWEEP_OPERATOR", "alice")
    st = Store(home); st.init("T", "c", "alice")
    st.scope_path.write_text(_j.dumps({"engagement": "T", "window": {"start": "2020-01-01T00:00:00Z", "end": "2099-01-01T00:00:00Z"},
                                       "in_scope": {"hosts": ["127.0.0.1"]}, "out_of_scope": [], "forbidden_actions": [], "roles": {}, "tripwires": []}))
    assert cli.main(["wrap", "--host", "127.0.0.1", "--", sys.executable, "-c", "import time; time.sleep(1.2)"]) == 0
    a = Store(home) and __import__("redsweep.state", fromlist=["build"]).build(Store(home)).actions[0]
    from redsweep.util import parse_time
    assert (parse_time(a["recorded"]) - parse_time(a["t"])).total_seconds() >= 1  # stamped when it began, not when it ended


def test_review_does_not_match_different_ip_addresses(eng):
    from redsweep.util import parse_time
    eng.log_action("on .13", host="127.0.0.1", at="2026-10-03T10:00:00Z")
    blue = [{"t": parse_time("2026-10-03T10:00:05Z"), "host": "127.0.0.12", "source": "x", "summary": "s", "level": "L1", "ref": ""}]
    r = review.review(eng.state(), blue, 30)
    assert r["seen"] == 0 and len(r["unmatched_blue"]) == 1  # same first octet is not the same host
    assert review._host_match("ws1.lab.example", "WS1") and not review._host_match("10.0.0.1", "10.0.0.2")


def test_review_scores_failed_attempts_too(eng):
    from redsweep.util import parse_time
    eng.log_action("wrong password", host="dc1.lab.example", result="fail", at="2026-10-03T10:00:00Z")
    eng.log_action("only planned", host="dc1.lab.example", result="planned", at="2026-10-03T10:01:00Z")
    blue = [{"t": parse_time("2026-10-03T10:00:04Z"), "host": "dc1", "source": "Security-4625", "summary": "s", "level": "L1", "ref": ""}]
    r = review.review(eng.state(), blue, 30)
    assert len(r["actions"]) == 1 and r["seen"] == 1  # the failed logon is scored; the planned one is not
