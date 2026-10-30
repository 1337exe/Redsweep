"""Replay a GOAD-shaped engagement from files. The data is SYNTHETIC: host names follow GOAD's published layout, the blue timeline is in
the exact format the Windows Security-log export produces, and nothing was run on a real range. It checks that the import, review and
Navigator steps work on that shape of data end to end. Usage: python replay.py [WORKDIR]"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
W = Path(sys.argv[1] if len(sys.argv) > 1 else Path(tempfile.gettempdir()) / "lowtide-goad-replay").resolve()
HOME = W / ".lowtide"


def lt(op, *args):
    env = dict(os.environ, LOWTIDE_HOME=str(HOME), LOWTIDE_OPERATOR=op, PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-m", "lowtide", *args], env=env, capture_output=True, text=True, encoding="utf-8")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    if W.exists():
        shutil.rmtree(W)
    W.mkdir(parents=True)
    lt("alpha", "init", "--name", "GOAD-REPLAY", "--client", "GOAD-shaped synthetic data")
    (HOME / "scope.json").write_text('{"engagement":"GOAD-REPLAY","window":{"start":"2026-10-01T00:00:00Z","end":"2026-12-31T23:59:59Z"},'
                                     '"in_scope":{"hosts":["*.sevenkingdoms.local"],"cloud_projects":[],"accounts":[]},"out_of_scope":[],'
                                     '"forbidden_actions":["denial-of-service"],"roles":{"control_team":["casey"],"red_lead":["alpha"]},"tripwires":[]}')
    rc, o = lt("alpha", "import", "csv", str(HERE / "operator-log.csv"), "--map", "time=time", "--map", "text=text", "--map", "host=host",
               "--map", "result=result", "--map", "class=class", "--map", "operator=operator")
    print(o.strip())
    rc2, o = lt("alpha", "import", "csv", str(HERE / "operator-log.csv"), "--map", "time=time", "--map", "text=text", "--map", "host=host",
                "--map", "result=result", "--map", "class=class", "--map", "operator=operator")
    print("second import:", o.strip())
    rc2 = rc2 if "added 0 entries, skipped 8" in o else 1
    rc3, o = lt("alpha", "review", str(HERE / "blue-timeline.csv"), "--window", "30")
    (W / "review.txt").write_text(o)
    print(o)
    rc4, o = lt("alpha", "navigator", str(HERE / "blue-timeline.csv"), "--out", str(W / "navigator.json"))
    print(o.strip())
    review_text = (W / "review.txt").read_text()
    ok = (rc == 0 and rc2 == 0 and rc3 == 0 and rc4 == 0 and "3 of 8 actions were seen" in review_text)
    print(f"\nreplay folder: {W}")
    print("REPLAY RESULT:", "as expected (3 of 8 actions seen, second import added nothing)" if ok else "UNEXPECTED, see above")
    return 0 if ok else 1


sys.exit(main())
