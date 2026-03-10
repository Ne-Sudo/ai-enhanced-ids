# Intrusion Prevention System module.
# Translates IDS alerts into Windows Firewall block rules via PowerShell.

import subprocess
import ipaddress
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Private / loopback ranges that shouldn't be auto-blocked.
# ---------------------------------------------------------------------------
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Severities that will trigger an automatic block.
# LOW / MEDIUM are left to be manually reviewed
BLOCK_SEVERITIES = {"CRITICAL", "HIGH"}


def _is_private(ip_str: str) -> bool:
    # Return True if the IP falls inside the loopback range
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # Malformed IP — do not block


def _rule_name(ip_str: str) -> str:
    # Returns a firewall rule name
    return f"IDS_BLOCK_{ip_str}"


def is_blocked(ip_str: str) -> bool:
    # Check whether a Windows Firewall inbound block rule already exists for this IP
    name = _rule_name(ip_str)
    cmd = [
        "powershell", "-NoProfile", "-Command",
        # Check for the _IN rule — if it exists, the pair was already created.
        f"Get-NetFirewallRule -DisplayName '{name}_IN' -ErrorAction SilentlyContinue"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return bool(result.stdout.strip())


def block_ip(ip_str: str) -> bool:
    # Add an inbound + outbound Windows Firewall block rule for ip_str.
    # Returns True on success, False if skipped or failed.
    if _is_private(ip_str):
        print(f"[IPS] Skipped private/loopback IP: {ip_str}")
        return False

    if is_blocked(ip_str):
        print(f"[IPS] Already blocked: {ip_str}")
        return False

    name = _rule_name(ip_str)

    # Block both inbound and outbound
    ps_script = (
        f"New-NetFirewallRule -DisplayName '{name}_IN' "
        f"-Direction Inbound -Action Block "
        f"-RemoteAddress '{ip_str}' -Protocol Any -Profile Any -Enabled True; "
        f"New-NetFirewallRule -DisplayName '{name}_OUT' "
        f"-Direction Outbound -Action Block "
        f"-RemoteAddress '{ip_str}' -Protocol Any -Profile Any -Enabled True"
    )

    cmd = ["powershell", "-NoProfile", "-Command", ps_script]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            print(f"[IPS ERROR] Failed to block {ip_str}: {result.stderr.strip()}")
            return False

        print(f"[IPS] Blocked: {ip_str}")
        return True

    except subprocess.TimeoutExpired:
        print(f"[IPS ERROR] Timeout while blocking {ip_str}")
        return False


def unblock_ip(ip_str: str) -> bool:
    # Remove the firewall rules for ip_str
    name = _rule_name(ip_str)
    ps_script = (
        f"Remove-NetFirewallRule -DisplayName '{name}_IN' -ErrorAction SilentlyContinue; "
        f"Remove-NetFirewallRule -DisplayName '{name}_OUT' -ErrorAction SilentlyContinue"
    )

    cmd = ["powershell", "-NoProfile", "-Command", ps_script]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[IPS] Unblocked: {ip_str}")
        return True

    print(f"[IPS ERROR] Could not unblock {ip_str}: {result.stderr.strip()}")
    return False


def log_block(block_log: Path, ip_str: str, severity: str, probability: float, pcap_name: str) -> None:
    # Add one row to the IPS log CSV
    block_log.parent.mkdir(parents=True, exist_ok=True)

    row = pd.DataFrame([{
        "time": datetime.now(timezone.utc).isoformat(),
        "src_ip": ip_str,
        "severity": severity,
        "probability": round(probability, 4),
        "pcap": pcap_name,
        "action": "BLOCKED"
    }])

    if not block_log.exists():
        row.to_csv(block_log, index=False)
    else:
        row.to_csv(block_log, mode="a", header=False, index=False)


def run_ips(
    results: pd.DataFrame,
    block_log: Path,
    pcap_name: str,
    extra_whitelist: list[str] | None = None
) -> int:
    # Iterate over scored results and block any source IP whose severity 
    # falls within BLOCK_SEVERITIES and is not whitelisted.
    whitelist = set(extra_whitelist or [])
    blocked_this_run = 0

    alerts = results[results["prediction"] == 1].copy()

    for _, row in alerts.iterrows():
        severity = str(row.get("severity", ""))
        src_ip = str(row.get("Src IP", ""))
        prob = float(row.get("malicious_prob", 0.0))

        if severity not in BLOCK_SEVERITIES:
            continue

        if not src_ip or src_ip in ("nan", "", "?"):
            continue

        if src_ip in whitelist:
            print(f"[IPS] Whitelisted, skipping: {src_ip}")
            continue

        if block_ip(src_ip):
            log_block(block_log, src_ip, severity, prob, pcap_name)
            blocked_this_run += 1

    return blocked_this_run