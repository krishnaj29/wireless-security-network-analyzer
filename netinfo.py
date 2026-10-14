"""
Wireless Security Network Analyzer - Local Network Info
Parses ipconfig /all to show this device's own network configuration.
"""

import subprocess
import re

def get_network_info():
    """
    Runs ipconfig /all and extracts info for the Wi-Fi adapter:
    IPv4 address, subnet mask, default gateway, DNS servers.
    Returns a dict.
    """
    result = subprocess.run(
        ["ipconfig", "/all"],
        capture_output=True, text=True, shell=True
    )
    output = result.stdout
    lines = output.splitlines()

    start_index = None
    for i, line in enumerate(lines):
        if "Wireless LAN adapter Wi-Fi" in line:
            start_index = i
            break

    if start_index is None:
        return {"ip_address": None, "subnet_mask": None, "gateway": None, "dns": None}

    section_lines = []
    for line in lines[start_index + 1:]:
        if re.match(r"^\S.*adapter.*:$", line.strip()):
            break  # next adapter section started
        section_lines.append(line)

    ip = subnet = gateway = dns = None

    for idx, line in enumerate(section_lines):
        stripped = line.strip()

        if "IPv4 Address" in stripped and ip is None:
            match = re.search(r":\s*([\d.]+)", stripped)
            if match:
                ip = match.group(1)

        elif "Subnet Mask" in stripped and subnet is None:
            match = re.search(r":\s*([\d.]+)", stripped)
            if match:
                subnet = match.group(1)

        elif "Default Gateway" in stripped and gateway is None:
            match = re.search(r":\s*([\d.]+)$", stripped)
            if match:
                gateway = match.group(1)
            else:
                if idx + 1 < len(section_lines):
                    next_line = section_lines[idx + 1].strip()
                    match2 = re.match(r"^([\d.]+)$", next_line)
                    if match2:
                        gateway = match2.group(1)

        elif "DNS Servers" in stripped and dns is None:
            match = re.search(r":\s*([\d.]+)$", stripped)
            if match:
                dns = match.group(1)
            else:
                if idx + 1 < len(section_lines):
                    next_line = section_lines[idx + 1].strip()
                    match2 = re.match(r"^([\d.]+)$", next_line)
                    if match2:
                        dns = match2.group(1)

    return {
        "ip_address": ip,
        "subnet_mask": subnet,
        "gateway": gateway,
        "dns": dns
    }