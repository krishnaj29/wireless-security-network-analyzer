"""
Wireless Security Network Analyzer
-----------------------------------
Scans nearby WiFi networks using Windows' built-in netsh command,
parses the output, and assigns a security risk score to each network.
"""

import subprocess
import re

def run_netsh_scan():
    """Runs the netsh command and returns raw text output."""
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, shell=True
    )
    return result.stdout


def parse_networks(raw_output):
    """
    Parses netsh output into a list of dicts, one per SSID block.
    Each dict includes ssid, auth, encryption, and a list of BSSIDs with signal info.
    """
    networks = []
    current = None
    current_bssid = None

    lines = raw_output.splitlines()

    for line in lines:
        line = line.strip()

        ssid_match = re.match(r"SSID \d+ : (.*)", line)
        if ssid_match:
            if current:
                networks.append(current)
            current = {
                "ssid": ssid_match.group(1).strip() or "(hidden)",
                "auth": None,
                "encryption": None,
                "bssids": []
            }
            current_bssid = None
            continue

        if current is None:
            continue

        auth_match = re.match(r"Authentication\s*:\s*(.*)", line)
        if auth_match:
            current["auth"] = auth_match.group(1).strip()
            continue

        enc_match = re.match(r"Encryption\s*:\s*(.*)", line)
        if enc_match:
            current["encryption"] = enc_match.group(1).strip()
            continue

        bssid_match = re.match(r"BSSID \d+\s*:\s*(.*)", line)
        if bssid_match:
            current_bssid = {"bssid": bssid_match.group(1).strip(), "signal": None, "channel": None}
            current["bssids"].append(current_bssid)
            continue

        signal_match = re.match(r"Signal\s*:\s*(\d+)%", line)
        if signal_match and current_bssid:
            current_bssid["signal"] = int(signal_match.group(1))
            continue

        channel_match = re.match(r"Channel\s*:\s*(\d+)", line)
        if channel_match and current_bssid:
            current_bssid["channel"] = int(channel_match.group(1))
            continue

    if current:
        networks.append(current)

    return networks


def score_network(network):
    """
    Assigns a risk level and reason based on auth/encryption type.
    Returns (risk_level, reason)
    """
    auth = (network["auth"] or "").upper()
    encryption = (network["encryption"] or "").upper()

    if "OPEN" in auth or encryption == "NONE":
        return "HIGH", "Open network — no encryption, traffic is visible to anyone nearby"
    if "WEP" in auth:
        return "HIGH", "WEP encryption — outdated and crackable in minutes"
    if "WPA2" in auth and "PERSONAL" in auth:
        return "MEDIUM", "WPA2-Personal — reasonably secure but vulnerable to weak passwords"
    if "WPA3" in auth:
        return "LOW", "WPA3 — current best-practice encryption"
    if "WPA" in auth:
        return "MEDIUM", "WPA (older) — consider upgrading to WPA2/WPA3"
    return "UNKNOWN", "Could not determine security type"


def main():
    print("Scanning nearby WiFi networks...\n")
    raw = run_netsh_scan()
    networks = parse_networks(raw)

    if not networks:
        print("No networks found. Make sure WiFi is turned on.")
        return

    print(f"{'SSID':25} {'Auth':18} {'Risk':8} {'Reason'}")
    print("-" * 100)

    for net in networks:
        risk, reason = score_network(net)
        print(f"{net['ssid']:25} {net['auth'] or '-':18} {risk:8} {reason}")

    print(f"\nTotal networks found: {len(networks)}")


if __name__ == "__main__":
    main()