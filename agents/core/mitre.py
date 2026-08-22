"""Mapping from attacker shell commands to MITRE ATT&CK (Enterprise) techniques.

Scope declared in the TFM (section 1.4.1) centres on T1087, T1082 and T1083;
the surrounding techniques are included so the SOC alert carries the full
reconnaissance picture rather than three isolated tactics.
"""
from __future__ import annotations

import re

# (compiled pattern, technique id, technique name, tactic, base severity 1-10)
_RULES: list[tuple[re.Pattern[str], str, str, str, int]] = [
    (re.compile(r"^\s*(whoami|id|groups|who|w|last|lastlog)\b"),
     "T1033", "System Owner/User Discovery", "Discovery", 4),
    (re.compile(r"(/etc/passwd|/etc/shadow|/etc/group|\bgetent\b|\bcut -d.?:.?\b.*passwd)"),
     "T1087.001", "Account Discovery: Local Account", "Discovery", 7),
    (re.compile(r"^\s*(uname|hostnamectl|lscpu|lsb_release|dmidecode|free|df|hostname|arch)\b"),
     "T1082", "System Information Discovery", "Discovery", 4),
    (re.compile(r"^\s*(ls|dir|find|tree|locate|du|stat|file)\b"),
     "T1083", "File and Directory Discovery", "Discovery", 3),
    (re.compile(r"^\s*(ps|top|htop|pgrep|pidof|lsof)\b"),
     "T1057", "Process Discovery", "Discovery", 4),
    (re.compile(r"^\s*(ip|ifconfig|netstat|ss|route|arp|iptables|nft)\b"),
     "T1016", "System Network Configuration Discovery", "Discovery", 5),
    (re.compile(r"^\s*(nmap|masscan|ping|traceroute|nc|ncat|telnet)\b"),
     "T1046", "Network Service Discovery", "Lateral Movement", 7),
    (re.compile(r"^\s*(sudo|su)\b|\bpkexec\b|\bsetuid\b|find .*-perm.*[24]000"),
     "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
     "Privilege Escalation", 8),
    (re.compile(r"(\.ssh/|authorized_keys|id_rsa|id_ed25519|known_hosts)"),
     "T1552.004", "Unsecured Credentials: Private Keys", "Credential Access", 9),
    (re.compile(r"(\.bash_history|\.mysql_history|\.env\b|credentials|\.aws/|\.git-credentials)"),
     "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access", 8),
    (re.compile(r"^\s*(wget|curl|scp|rsync|ftp|tftp)\b"),
     "T1105", "Ingress Tool Transfer", "Command and Control", 8),
    (re.compile(r"(crontab|/etc/cron|systemctl (enable|start)|/etc/rc\.local|\.service\b)"),
     "T1053.003", "Scheduled Task/Job: Cron", "Persistence", 8),
    (re.compile(r"(useradd|adduser|usermod|passwd\s+\w|chpasswd)"),
     "T1136.001", "Create Account: Local Account", "Persistence", 8),
    (re.compile(r"(history -c|rm -rf|shred|>\s*/var/log|truncate .*log|unset HISTFILE)"),
     "T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion", 9),
    (re.compile(r"(base64|xxd|openssl enc|gpg\b|/dev/tcp/)"),
     "T1027", "Obfuscated Files or Information", "Defense Evasion", 7),
    (re.compile(r"(docker|kubectl|/var/run/docker\.sock|/proc/1/cgroup|/\.dockerenv)"),
     "T1610", "Deploy Container", "Execution", 8),
    (re.compile(r"^\s*(cat|less|more|head|tail|grep|nano|vi|vim)\b"),
     "T1005", "Data from Local System", "Collection", 3),
    (re.compile(r"^\s*(tar|zip|gzip|7z)\b"),
     "T1560.001", "Archive Collected Data via Utility", "Collection", 6),
]

_UNMAPPED = ("T0000", "Unclassified Interaction", "Unknown", 2)


def classify(command: str) -> dict[str, object]:
    """Return the ATT&CK techniques matched by a single command line.

    A command can legitimately match several rules (``cat /etc/passwd`` is both
    Collection and Account Discovery); all matches are returned and severity is
    the maximum, so a compound command is never under-scored.
    """
    matches: list[dict[str, str]] = []
    severity = 0
    for pattern, tid, name, tactic, sev in _RULES:
        if pattern.search(command):
            matches.append({"technique_id": tid, "technique": name, "tactic": tactic})
            severity = max(severity, sev)

    if not matches:
        tid, name, tactic, sev = _UNMAPPED
        matches.append({"technique_id": tid, "technique": name, "tactic": tactic})
        severity = sev

    return {
        "techniques": matches,
        "severity": severity,
        "primary_technique": matches[0]["technique_id"],
    }
