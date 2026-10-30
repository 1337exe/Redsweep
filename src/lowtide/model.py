"""Fixed vocabularies: what kinds of things an engagement can leave behind, and how each one is cleaned up."""
from __future__ import annotations

# Things that change state on a target or on the operator side and must be undone or handed over.
CHANGE_KINDS = {
    "config": "a setting or file you changed",
    "file": "a file you created or modified on a target",
    "account": "an account, group membership or role you created or changed",
    "persistence": "a way back in (scheduled task, service, run key, cron, authorized_keys)",
    "implant": "an agent or beacon running on a target",
    "iam": "a cloud policy, role or binding change",
    "infra": "red infrastructure (server, redirector, listener, landing page)",
    "domain": "a domain or DNS record you registered or changed",
    "data": "data you copied, staged or created on a target",
    "other": "anything else that changed state",
}
AUTONOMOUS_KINDS = {"implant", "persistence", "infra"}  # keep running without an operator

# How the engagement is torn down. Order matters and follows the order in which things should be undone.
TEARDOWN_ORDER = ["implant", "persistence", "account", "iam", "config", "file", "data", "infra", "domain", "other"]

# Credential families: how long they live, whether they can be revoked, and what containment means for each.
FAMILIES = {
    "kerberos-ticket": {"lifetime": 36000, "steps": [
        "delete ticket files from operator and target hosts (kirbi / ccache)",
        "record ticket expiry (UTC)",
        "tell the Control Team which accounts had tickets issued so the client can decide on password or key resets"]},
    "ntlm-hash": {"lifetime": None, "steps": [
        "delete the hash from operator notes and tooling",
        "list the account for the client's rotation list"]},
    "password": {"lifetime": None, "steps": [
        "delete from operator notes and tooling",
        "list the account for the client's rotation list"]},
    "gcp-sa-key": {"lifetime": 3600, "steps": [
        "delete local copies of the key file",
        "revoke local CLI state for the account",
        "disable the key (client side), then delete it once dependencies are checked",
        "record the issued-token window"]},
    "gcp-access-token": {"lifetime": 3600, "steps": [
        "delete local copies",
        "record the latest possible issue time and the documented lifetime"]},
    "oauth-refresh": {"lifetime": None, "steps": [
        "delete local copies",
        "revoke at the provider's revocation endpoint",
        "record how long propagation took"]},
    "aws-session": {"lifetime": 3600, "steps": [
        "delete from environment, shell history and credential files",
        "record the session expiry (UTC)"]},
    "aws-access-key": {"lifetime": None, "steps": [
        "delete local copies",
        "deactivate the key (client side), then delete it"]},
    "azure-token": {"lifetime": 5400, "steps": [
        "delete local token caches",
        "ask the client to revoke sign-in sessions if an early stop is needed",
        "record the token expiry (UTC)"]},
    "api-key": {"lifetime": None, "steps": ["delete local copies", "list the key for the client's rotation list"]},
    "session-cookie": {"lifetime": 3600, "steps": ["delete local copies", "record the session expiry (UTC)"]},
    "ssh-key": {"lifetime": None, "steps": [
        "remove the public key from every authorized_keys you touched (ledger item)",
        "delete the private key from operator systems"]},
    "certificate": {"lifetime": None, "steps": ["delete local copies", "ask the client to revoke the certificate"]},
    "other": {"lifetime": None, "steps": ["delete local copies", "list for the client"]},
}

LADDER = ["authority", "metadata", "canary", "real-record"]  # least to most sensitive evidence
LADDER_HELP = {"authority": "proof you could do it (a permission, a role, a control that is enabled)",
               "metadata": "counts, sizes, names, schema",
               "canary": "a planted synthetic record, proven by digest",
               "real-record": "a real customer record (almost never needed; needs Control Team approval)"}

LEVELS = {  # default detection scale, editable in config.json
    "L0": "telemetry exists, nobody looked",
    "L1": "an automated alert fired, nobody triaged it",
    "L2": "an analyst looked at it",
    "L3": "treated as malicious: an incident was opened",
    "L4": "responders acted against red assets (isolation, blocks, resets)",
    "L5": "the escalation left the security function (management, legal, regulators, police)",
}

STOP_CONDITIONS = {
    "other-intruder": "signs of another intruder on the target",
    "unexpected-impact": "unexpected impact on a production system",
    "out-of-scope-contact": "contact with a system or party that is out of scope",
    "tooling-control-lost": "you no longer control your own tooling or infrastructure",
    "channel-lost": "the Control Team channel is lost",
}

DECISION_OPTIONS = ["continue", "go-dark", "burn-and-pivot", "leg-up", "limited-purple", "suspend", "end-scenario"]

ERROR_LAYERS = ["local-config", "network-path", "time", "authentication", "authorization", "target-state", "tooling", "n/a"]

DEFAULT_CONFIG = {
    "strict_scope": True,            # a target that is not listed in scope is refused, not guessed
    "require_second_operator": False,  # the read-back must come from someone other than the person who rolled back
    "min_verify_strength": "attested",  # auto | manual | attested
    "assumption_stop_after": 2,      # same assumption fails this many times with no new information: stop and log why
    "sitrep_requires_log": True,     # a SITREP must cite operator log entries
    "levels": LEVELS,
}
STRENGTH_RANK = {"attested": 1, "manual": 2, "auto": 3}
