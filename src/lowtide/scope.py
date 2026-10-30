"""Rules of engagement as code. A target is in scope, out of scope, or unlisted; unlisted is treated as out when strict."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
from urllib.parse import urlparse

from .util import parse_time, now


class ScopeError(Exception):
    pass


def host_of(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    t = t.split("/")[0]
    if t.count(":") == 1:  # host:port
        t = t.split(":")[0]
    return t.strip("[]").lower()


class Scope:
    def __init__(self, data: dict):
        self.d = data
        self.window = data.get("window") or {}
        ins = data.get("in_scope") or {}
        self.inc = [x.lower() for x in (ins.get("hosts") or []) + (ins.get("cloud_projects") or []) + (ins.get("accounts") or [])]
        self.exc = [x.lower() for x in (data.get("out_of_scope") or [])]
        self.forbidden = set(data.get("forbidden_actions") or [])
        self.roles = data.get("roles") or {}
        self.tripwires = list(data.get("tripwires") or [])

    @classmethod
    def load(cls, path):
        try:
            with open(path, encoding="utf-8") as fh:
                return cls(json.load(fh))
        except FileNotFoundError:
            raise ScopeError(f"scope file not found: {path}")
        except ValueError as e:
            raise ScopeError(f"scope file is not valid JSON: {e}")

    @staticmethod
    def _match(h: str, pat: str) -> bool:
        if "/" in pat:
            try:
                return ipaddress.ip_address(h) in ipaddress.ip_network(pat, strict=False)
            except ValueError:
                return False
        return fnmatch.fnmatchcase(h, pat) or h == pat

    def check(self, target: str):
        """-> ("in"|"out"|"unlisted", reason)"""
        h = host_of(target)
        if not h:
            return "unlisted", "empty target"
        for p in self.exc:
            if self._match(h, p):
                return "out", f"matches out-of-scope rule {p!r}"
        for p in self.inc:
            if self._match(h, p):
                return "in", f"matches in-scope rule {p!r}"
        return "unlisted", "not listed in scope; treat as out of scope until the Control Team says otherwise"

    def check_action(self, cls: str):
        if cls in self.forbidden:
            return "forbidden", f"{cls!r} is on the forbidden-action list"
        return "ok", ""

    def check_window(self, at=None):
        a, b = self.window.get("start"), self.window.get("end")
        t = parse_time(at) if at else now()
        if a and t < parse_time(a):
            return False, f"before the testing window opens ({a})"
        if b and t > parse_time(b):
            return False, f"after the testing window closed ({b})"
        return True, ""

    def is_ct(self, name: str) -> bool:
        ct = self.roles.get("control_team") or []
        return (not ct) or name in ct  # if no Control Team is named, nobody can be refused; init warns about this
