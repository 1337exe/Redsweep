"""The journal: one append-only, hash-chained file per operator. Nothing is edited; state is always rebuilt from events."""
from __future__ import annotations

import json
import os
import threading
import time
import re
from pathlib import Path

from . import __version__
from .model import DEFAULT_CONFIG
from .util import canon, iso, now, parse_time, sha256_text

try:
    import fcntl
except ImportError:  # Windows has no fcntl; msvcrt locks one byte instead
    fcntl = None
try:
    import msvcrt
except ImportError:
    msvcrt = None

_LOCK_AT = 1 << 30  # lock a byte far past the data so readers of the journal are never blocked
_THREAD_LOCK = threading.RLock()  # msvcrt locks are per process; this keeps threads in one process in line


def _lock(fh):
    if fcntl:
        fcntl.flock(fh, fcntl.LOCK_EX)
    elif msvcrt:
        while True:
            try:
                fh.seek(_LOCK_AT)
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:
                time.sleep(0.05)


def _unlock(fh):
    if fcntl:
        fcntl.flock(fh, fcntl.LOCK_UN)
    elif msvcrt:
        fh.seek(_LOCK_AT)
        try:
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass

GENESIS = "0" * 64
OP_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def _last_line(fh) -> str:
    """The last non-empty line of an append-mode file, found by reading backwards (so appends stay fast on big journals)."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if not size:
        return ""
    chunk = 8192
    data = b""
    with open(fh.name, "rb") as raw:
        pos = size
        while pos > 0:
            pos = max(0, pos - chunk)
            raw.seek(pos)
            data = raw.read(size - pos)
            lines = [l for l in data.splitlines() if l.strip()]
            if len(lines) >= 2 or pos == 0:
                return lines[-1].decode("utf-8") if lines else ""
    return ""


class StoreError(Exception):
    pass


def _chain(prev: str, body: dict) -> str:
    return sha256_text(prev + canon(body))


class Store:
    def __init__(self, home=None):
        self.home = Path(home or os.environ.get("LOWTIDE_HOME") or ".lowtide")

    # ---- layout
    @property
    def jdir(self) -> Path:
        return self.home / "journal"

    @property
    def config_path(self) -> Path:
        return self.home / "config.json"

    @property
    def scope_path(self) -> Path:
        return self.home / "scope.json"

    def exists(self) -> bool:
        return self.config_path.exists()

    def require(self):
        if not self.exists():
            raise StoreError(f"no engagement at {self.home}. Run `lowtide init` first (or set LOWTIDE_HOME / --home).")

    # ---- config
    def cfg(self) -> dict:
        c = dict(DEFAULT_CONFIG)
        if self.config_path.exists():
            try:
                user = json.loads(self.config_path.read_text())
            except ValueError as e:
                raise StoreError(f"{self.config_path} is not valid JSON: {e}")
            unknown = set(user) - set(DEFAULT_CONFIG) - {"name", "client", "default_operator"}
            if unknown:
                raise StoreError(f"unknown config keys: {sorted(unknown)}")
            c.update(user)
        return c

    def operator(self, override=None) -> str:
        op = override or os.environ.get("LOWTIDE_OPERATOR") or self.cfg().get("default_operator") or os.environ.get("USER") or "operator"
        if not OP_RE.match(op):
            raise StoreError(f"operator name {op!r} must be 1-32 characters from A-Z a-z 0-9 _ . -")
        return op

    # ---- init
    def init(self, name: str, client: str = "", operator: str = "", force: bool = False):
        if self.exists() and not force:
            raise StoreError(f"{self.home} already holds an engagement (use --force to overwrite config)")
        self.jdir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        cfg = {"name": name, "client": client}
        if operator:
            cfg["default_operator"] = operator
        self.config_path.write_text(json.dumps(cfg, indent=2) + "\n")
        if not self.scope_path.exists():
            self.scope_path.write_text(json.dumps(STARTER_SCOPE, indent=2) + "\n")
        return self.append("init", {"name": name, "client": client, "version": __version__}, operator=operator or None)

    # ---- append
    def append(self, kind: str, data: dict, operator=None, at=None, ref_prefix=None) -> dict:
        op = self.operator(operator)
        self.jdir.mkdir(parents=True, exist_ok=True)
        path = self.jdir / f"{op}.jsonl"
        if not path.exists():
            path.touch(mode=0o600)
        with _THREAD_LOCK, open(path, "a+", encoding="utf-8") as fh:
            _lock(fh)
            prev, seq = GENESIS, 0
            last = _last_line(fh)
            if last:
                r = json.loads(last)
                prev, seq = r["hash"], r["seq"]
            seq += 1
            t = iso(parse_time(at) if at else now())
            ev = {"v": 1, "seq": seq, "t": t, "op": op, "kind": kind, "data": data, "prev": prev}
            if ref_prefix:
                ev["id"] = ref_prefix + sha256_text(f"{op}:{seq}:{t}:{kind}")[:5]
            ev["hash"] = _chain(prev, {k: v for k, v in ev.items() if k != "hash"})
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            _unlock(fh)
        return ev

    # ---- read and verify
    def files(self):
        return sorted(self.jdir.glob("*.jsonl")) if self.jdir.exists() else []

    def verify_file(self, path: Path):
        prev, n = GENESIS, 0
        try:
            with open(path, encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    r = json.loads(line)
                    h = r.pop("hash", None)
                    if r.get("prev") != prev or r.get("seq") != n + 1 or _chain(prev, r) != h:
                        return False, n, f"chain broken at line {i} (seq {r.get('seq')})"
                    prev, n = h, n + 1
        except (ValueError, OSError) as e:
            return False, n, f"unreadable: {e}"
        return True, n, prev

    def verify(self):
        """[(file name, ok, event count, head hash or message)]"""
        return [(p.name, *self.verify_file(p)) for p in self.files()]

    def events(self):
        """All events from every operator, oldest first. Returns (events, problems)."""
        evs, problems = [], []
        for p in self.files():
            ok, n, info = self.verify_file(p)
            if not ok:
                problems.append(f"{p.name}: {info}")
            with open(p, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        try:
                            evs.append(json.loads(line))
                        except ValueError:
                            pass
        evs.sort(key=lambda e: (e["t"], e["op"], e["seq"]))
        return evs, problems


STARTER_SCOPE = {
    "engagement": "EDIT ME",
    "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
    "in_scope": {"hosts": ["*.lab.example", "10.99.0.0/16"], "cloud_projects": [], "accounts": []},
    "out_of_scope": ["*.mdr-provider.example", "10.99.250.0/24"],
    "forbidden_actions": ["payment-approval-click", "denial-of-service", "real-data-exfil"],
    "roles": {"control_team": [], "red_lead": []},
    "tripwires": ["external_party", "production_containment", "exec_crisis"],
}
