"""Seal and pack. A seal fixes the journal heads and the reports. A pack is a zip anyone can check without Lowtide's state."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from . import __version__
from .store import Store
from .util import iso, now, sha256_text, canon

MAX_PACK_BYTES = 200 * 1024 * 1024


class SealError(Exception):
    pass


def _key(key_file=None):
    if key_file:
        return Path(key_file).read_bytes().strip()
    k = os.environ.get("LOWTIDE_KEY")
    return k.encode() if k else None


def dump(seal_body: dict) -> str:
    """The one way a seal is written to disk, so a signature over the file still matches the copy inside the pack."""
    return json.dumps(seal_body, indent=2) + "\n"


def make_seal(store: Store, reports: dict, key_file=None):
    heads = {}
    for name, ok, n, info in store.verify():
        if not ok:
            raise SealError(f"cannot seal: {name}: {info}")
        heads[name] = {"events": n, "head": info}
    body = {"lowtide": __version__, "sealed_at": iso(now()), "journals": heads,
            "reports": {k: sha256_text(v) for k, v in reports.items()}}
    k = _key(key_file)
    if k:
        body["hmac_sha256"] = hmac.new(k, canon({x: body[x] for x in body if x != "hmac_sha256"}).encode(), hashlib.sha256).hexdigest()
    return body


def check_seal(body: dict, key_file=None):
    k = _key(key_file)
    if "hmac_sha256" not in body:
        return "unsigned"
    if not k:
        return "signed (no key given, not checked)"
    want = hmac.new(k, canon({x: body[x] for x in body if x != "hmac_sha256"}).encode(), hashlib.sha256).hexdigest()
    return "signature OK" if hmac.compare_digest(want, body["hmac_sha256"]) else "SIGNATURE DOES NOT MATCH"


def gpg_sign(path: str, key_id: str) -> str:
    """Detached, armoured signature of a file with the key you name. Needs gpg on the machine. Returns the .asc path."""
    if not shutil.which("gpg"):
        raise SealError("gpg is not installed")
    asc = path + ".asc"
    p = subprocess.run(["gpg", "--batch", "--yes", "--armor", "--detach-sign", "-u", key_id, "-o", asc, path], capture_output=True, text=True)
    if p.returncode != 0:
        raise SealError("gpg could not sign: " + (p.stderr.strip().splitlines() or ["unknown error"])[-1])
    return asc


def gpg_verify(sig: bytes, data: bytes):
    """-> (ok, message). The result depends on the verifier's own keyring: a good signature from a key you do not trust is only 'valid'."""
    if not shutil.which("gpg"):
        return None, "signature present, but gpg is not installed so it was not checked"
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "d").write_bytes(data)
        (Path(td) / "d.asc").write_bytes(sig)
        p = subprocess.run(["gpg", "--batch", "--verify", str(Path(td) / "d.asc"), str(Path(td) / "d")], capture_output=True, text=True)
    lines = [l.replace("gpg: ", "") for l in p.stderr.splitlines() if "signature" in l.lower() or "using" in l.lower() or "no public key" in l.lower()]
    return p.returncode == 0, "gpg: " + ("; ".join(lines) if lines else ("good signature" if p.returncode == 0 else "verification failed"))


def build_pack(store: Store, out: str, reports: dict, seal: dict, extra: dict | None = None):
    files = {}
    for p in store.files():
        files[f"journal/{p.name}"] = p.read_bytes()
    for name in ("config.json", "scope.json"):
        fp = store.home / name
        if fp.exists():
            files[name] = fp.read_bytes()
    for name, text in reports.items():
        files[name] = text.encode()
    files["seal.json"] = dump(seal).encode()
    for name, data in (extra or {}).items():
        files[name] = data
    manifest = "".join(f"{hashlib.sha256(v).hexdigest()}  {k}\n" for k, v in sorted(files.items()))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in sorted(files.items()):
            z.writestr(k, v)
        z.writestr("MANIFEST.sha256", manifest)
    return out, len(files) + 1


def verify_pack(path: str, key_file=None):
    """-> (ok, [messages]). Reads the zip in memory; never extracts to disk."""
    msgs, ok = [], True
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        return False, [f"not a readable zip: {e}"]
    total = 0
    with z:
        names = z.namelist()
        for n in names:
            if n.startswith("/") or ".." in Path(n).parts:
                return False, [f"unsafe path in zip: {n}"]
        total = sum(i.file_size for i in z.infolist())
        if total > MAX_PACK_BYTES:
            return False, [f"zip expands to {total} bytes, over the {MAX_PACK_BYTES} limit"]
        if "MANIFEST.sha256" not in names:
            return False, ["MANIFEST.sha256 is missing"]
        listed = {}
        for line in z.read("MANIFEST.sha256").decode().splitlines():
            h, _, n = line.partition("  ")
            listed[n] = h
        for n in names:
            if n == "MANIFEST.sha256":
                continue
            if n not in listed:
                ok = False
                msgs.append(f"file not in manifest: {n}")
            elif hashlib.sha256(z.read(n)).hexdigest() != listed[n]:
                ok = False
                msgs.append(f"HASH MISMATCH: {n}")
        for n in listed:
            if n not in names:
                ok = False
                msgs.append(f"listed but missing: {n}")
        with tempfile.TemporaryDirectory() as td:
            st = Store(td)
            st.jdir.mkdir(parents=True)
            for n in names:
                if n.startswith("journal/") and n.endswith(".jsonl"):
                    (st.jdir / Path(n).name).write_bytes(z.read(n))
            chain = {name: (o, c, i) for name, o, c, i in st.verify()}
            for name, (o, c, i) in chain.items():
                if not o:
                    ok = False
                    msgs.append(f"journal {name}: {i}")
        if "seal.json" in names:
            seal = json.loads(z.read("seal.json"))
            for name, h in seal.get("journals", {}).items():
                if name not in chain or not chain[name][0] or chain[name][2] != h["head"] or chain[name][1] != h["events"]:
                    ok = False
                    msgs.append(f"seal does not match journal {name}")
            msgs.append("seal: " + check_seal(seal, key_file))
            if "DOES NOT MATCH" in msgs[-1]:
                ok = False
            if "seal.json.asc" in names:
                good, m = gpg_verify(z.read("seal.json.asc"), z.read("seal.json"))
                msgs.append(m)
                if good is False:
                    ok = False
    if ok:
        msgs.insert(0, f"{len(names)} files match the manifest; every journal chain is intact")
    return ok, msgs
