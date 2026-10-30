"""What an action leaves behind. Starting points taken from public Microsoft, Linux and cloud audit documentation.
Audit policy differs from site to site: confirm each row in your own lab before you rely on it."""
from __future__ import annotations

# class -> (cost, what it leaves, where it is recorded, events to look for, note)
PRICES = {
    "process-creation": ("medium", "a new process with its command line and parent", "endpoint, EDR, SIEM",
                         "Windows 4688 (if command-line auditing is on), Sysmon 1, Linux auditd EXECVE", "the most common record; parent and command line are what analysts read first"),
    "powershell": ("medium", "script text and engine start", "endpoint, EDR",
                   "PowerShell 4103 and 4104 (script block logging), Sysmon 1", "block logging keeps decoded script text"),
    "write-to-disk": ("medium", "a file on disk that antivirus and cloud reputation can read", "endpoint, EDR, cloud reputation",
                      "Sysmon 11, antivirus scan events", "a tool dropped to disk should be treated as known once it is scanned"),
    "lsass-access": ("high", "a handle opened to the credential process", "EDR, Sysmon",
                     "Sysmon 10 (TargetImage lsass.exe), EDR process-access telemetry, Security 4656/4663 with auditing", "among the first things defenders alert on"),
    "kerberos-ticket-request": ("medium", "ticket requests at the domain controller", "domain controller",
                                "Security 4768 (TGT), 4769 (service ticket), 4771 (failure)", "odd encryption types and bulk requests stand out"),
    "bulk-kerberoast": ("high", "many service ticket requests from one account in a short time", "domain controller, identity protection",
                        "Security 4769 in volume", "request only the accounts you need"),
    "ldap-bulk-query": ("high", "large directory reads from an unusual host", "domain controller, identity protection",
                        "expensive-search logging (event 1644 if enabled), identity protection alerts", "baselines of who normally queries the directory make this stand out"),
    "bloodhound-full-collection": ("high", "directory reads, group-membership queries and session enumeration across many hosts", "domain controllers, endpoints, identity protection",
                                   "LDAP volume, SAMR queries, 4624 from many hosts", "collect narrowly and analyse offline"),
    "remote-service-create": ("high", "a new service on a remote host", "target host",
                              "System 7045, Security 4697, 5145 for the admin share", "classic lateral-movement pattern; widely covered by rules"),
    "smb-admin-share-write": ("high", "a file written to an administrative share", "target host",
                              "Security 5140, 5145 (if detailed file share auditing is on)", ""),
    "network-logon": ("low", "a logon on the target", "target host, domain controller",
                      "Security 4624 (type 3), 4625, 4648, 4672", "fan-out logons from one source are the pattern to avoid"),
    "scheduled-task-create": ("medium", "a task definition on the host", "target host",
                              "Security 4698 (if enabled), TaskScheduler/Operational 106", "can sit in a SIEM for days with no rule"),
    "wmi-exec": ("medium", "a child process of the WMI provider host", "target host",
                 "WMI-Activity/Operational 5857-5861, Sysmon 1 with parent WmiPrvSE.exe", ""),
    "dcsync": ("high", "directory replication requests from a non-DC", "domain controller",
               "Security 4662 with replication rights", "replicate only the account you need"),
    "registry-run-key": ("medium", "a changed autorun registry value", "endpoint",
                         "Sysmon 12/13, Security 4657 if auditing is on", ""),
    "process-injection": ("high", "a remote thread or unbacked memory in another process", "EDR",
                          "Sysmon 8 and 10, EDR memory telemetry", "do not inject just to change identity; use credentials or tickets"),
    "network-beacon": ("medium", "repeated outbound connections with a regular rhythm", "proxy, DNS, firewall, EDR",
                       "Sysmon 3 and 22, proxy and DNS logs", "the process making the connection should normally make connections"),
    "ssh-login": ("low", "an authentication record on the host", "target host",
                  "auth.log or journal, auditd USER_LOGIN", ""),
    "sudo": ("low", "a privileged command record", "target host", "auth.log, auditd", ""),
    "cron-edit": ("medium", "a changed crontab", "target host", "syslog cron, auditd file watch if configured", ""),
    "authorized-keys-edit": ("medium", "a changed key file", "target host", "auditd file watch if configured, file integrity monitoring", ""),
    "user-add": ("medium", "a new local account", "target host", "auth.log (useradd), auditd ADD_USER, Windows 4720", ""),
    "gcp-generate-access-token": ("medium", "a service account token request", "Cloud Audit Logs (IAM Data Access, if enabled)",
                                  "iamcredentials GenerateAccessToken", "attribution may fall on the target account"),
    "gcp-secret-access": ("medium", "a read of a secret version", "Cloud Audit Logs (Data Access, if enabled)",
                          "secretmanager AccessSecretVersion", "the payload is not logged, the read is"),
    "gcp-role-update": ("high", "a custom role changed", "Cloud Audit Logs (Admin Activity, always on)",
                        "google.iam.admin.v1.UpdateRole", "the control grant survives the rollback"),
    "gcp-sa-key-create": ("high", "a new service account key", "Cloud Audit Logs (Admin Activity)", "CreateServiceAccountKey", ""),
    "gcp-asset-search": ("low", "a read of the asset index", "Cloud Audit Logs (Data Access, if enabled)", "cloudasset search and analyze calls", "policy analysis has a shared daily quota"),
    "aws-assume-role": ("medium", "a role assumption", "CloudTrail", "sts AssumeRole", ""),
    "aws-secret-read": ("medium", "a secret read", "CloudTrail", "secretsmanager GetSecretValue", ""),
    "aws-access-key-create": ("high", "a new access key", "CloudTrail", "iam CreateAccessKey", ""),
    "azure-signin": ("low", "a sign-in record", "Entra sign-in logs", "SignInLogs, AuditLogs", ""),
    "azure-graph-read": ("medium", "Graph reads under the app's identity", "Graph activity logs, if enabled", "MicrosoftGraphActivityLogs", ""),
}

COST_RANK = {"low": 1, "medium": 2, "high": 3}


def lookup(cls: str):
    return PRICES.get(cls)


def explain(cls: str) -> str:
    p = PRICES.get(cls)
    if not p:
        return f"{cls}: not in the price table. Add your own with the three questions (payoff, cost, reversibility)."
    cost, leaves, where, events, note = p
    s = f"{cls}  [{cost} cost]\n  leaves : {leaves}\n  seen in: {where}\n  events : {events}"
    return s + (f"\n  note   : {note}" if note else "")


# action class -> MITRE ATT&CK technique ID (enterprise). Used for the Navigator layer. Check against your own mapping before publishing.
TECHNIQUES = {
    "process-creation": "T1059", "powershell": "T1059.001", "write-to-disk": "T1105", "lsass-access": "T1003.001",
    "kerberos-ticket-request": "T1558", "bulk-kerberoast": "T1558.003", "ldap-bulk-query": "T1087.002",
    "bloodhound-full-collection": "T1069.002", "remote-service-create": "T1569.002", "smb-admin-share-write": "T1021.002",
    "network-logon": "T1078", "scheduled-task-create": "T1053.005", "wmi-exec": "T1047", "dcsync": "T1003.006",
    "registry-run-key": "T1547.001", "process-injection": "T1055", "network-beacon": "T1071.001", "ssh-login": "T1021.004",
    "sudo": "T1548.003", "cron-edit": "T1053.003", "authorized-keys-edit": "T1098.004", "user-add": "T1136.001",
    "gcp-generate-access-token": "T1078.004", "gcp-secret-access": "T1555.006", "gcp-role-update": "T1098.003",
    "gcp-sa-key-create": "T1098.001", "gcp-asset-search": "T1580", "aws-assume-role": "T1078.004", "aws-secret-read": "T1555.006",
    "aws-access-key-create": "T1098.001", "azure-signin": "T1078.004", "azure-graph-read": "T1087.004",
}
