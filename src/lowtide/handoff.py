"""The list the client needs once you leave: what to rotate, revoke, delete or keep an eye on."""
from __future__ import annotations

CLIENT_ASK = {
    "password": "reset the password", "ntlm-hash": "reset the password (the hash is derived from it)", "kerberos-ticket": "consider resetting the account; tickets expire on their own",
    "gcp-sa-key": "disable then delete the key; confirm the service account's recent use", "gcp-access-token": "no action; the token expires on its own",
    "oauth-refresh": "revoke the grant", "aws-session": "no action; the session expires on its own", "aws-access-key": "deactivate then delete the key",
    "azure-token": "revoke sign-in sessions if you want an early stop", "api-key": "rotate the key", "session-cookie": "no action; the session expires",
    "ssh-key": "remove the public key from authorized_keys on the listed hosts", "certificate": "revoke the certificate", "other": "review and rotate if unsure",
}


def build(st) -> str:
    L = ["# Client handoff", "", "Things that need an action on your side, or that you should know were left in a known state.", "", "## Credentials", ""]
    L.append("| Principal | Type | Host | Token valid until (UTC) | What we ask of you |")
    L.append("|---|---|---|---|---|")
    for k in st.creds.values():
        L.append(f"| {k['principal']} | {k['family']} | {k.get('host') or '-'} | {k.get('window_end') or '-'} | {CLIENT_ASK.get(k['family'], CLIENT_ASK['other'])} |")
    if not st.creds:
        L.append("| none | | | | |")
    L += ["", "## Control that remains after rollback", ""]
    rem = [c for c in st.changes.values() if c.get("durable")]
    L += [f"- {c['id']} {c['object']}: {c['durable']}" for c in rem] or ["- none recorded"]
    L += ["", "## Waived items (accepted by your side)", ""]
    wv = [c for c in st.changes.values() if c["status"] == "waived"]
    L += [f"- {c['id']} {c['object']} on {c.get('host') or '?'}: {c['waiver']['reason']} (accepted by {c['waiver']['by']})" for c in wv] or ["- none"]
    L += ["", "## Indicators you can use to check our work", ""]
    for c in st.changes.values():
        L.append(f"- {c['t']} {c['kind']} on {c.get('host') or '?'}: {c['object']}")
    return "\n".join(L) + "\n"
