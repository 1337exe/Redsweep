"""Small helpers: UTC time, hashing, canonical JSON."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

UTC = dt.timezone.utc


def now() -> dt.datetime:
    return dt.datetime.now(UTC)


def iso(d: dt.datetime) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(s) -> dt.datetime:
    """Parse a time. Times without a zone are read as UTC. Everything Lowtide stores is UTC."""
    if isinstance(s, dt.datetime):
        d = s
    else:
        s = str(s).strip()
        s2 = re.sub(r"\s*UTC$", "", s).replace("Z", "+00:00")
        try:
            d = dt.datetime.fromisoformat(s2)
        except ValueError:
            raise ValueError(f"cannot read time {s!r}; use ISO form such as 2026-10-30T14:22:11Z")
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return d.astimezone(UTC)


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def short(s: str, n: int = 90) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"
