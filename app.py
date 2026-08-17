"""
Wireless Security Network Analyzer - Web Dashboard
"""

from flask import Flask, render_template_string
from scanner import run_netsh_scan, parse_networks, score_network
from database import init_db, record_scan, get_first_seen, detect_duplicate_ssids
from netinfo import get_network_info

app = Flask(__name__)
init_db()  # ensure database exists on startup

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Wireless Security Network Analyzer</title>
    <meta http-equiv="refresh" content="15">
    <style>
        body { font-family: Arial, sans-serif; background: #1e1e2f; color: #eee; padding: 30px; }
        h1 { color: #4fd1c5; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #444; }
        th { background: #2a2a40; }
        .HIGH { color: #ff6b6b; font-weight: bold; }
        .MEDIUM { color: #ffd166; font-weight: bold; }
        .LOW { color: #6bff95; font-weight: bold; }
        .UNKNOWN { color: #aaa; font-weight: bold; }
        .subtitle { color: #999; }
        .new-badge { background: #4fd1c5; color: #1e1e2f; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-left: 8px; }
        .warning-box { background: #3a1f1f; border: 1px solid #ff6b6b; padding: 14px 18px; border-radius: 6px; margin-top: 20px; }
        .warning-box h3 { color: #ff6b6b; margin-top: 0; }
        .info-box { background: #1f2f3a; border: 1px solid #4fd1c5; padding: 14px 18px; border-radius: 6px; margin-top: 20px; }
        .info-box h3 { color: #4fd1c5; margin-top: 0; }
    </style>
</head>
<body>
    <h1>Wireless Security Network Analyzer</h1>
    <p class="subtitle">Auto-refreshes every 15 seconds &middot; {{ count }} networks found</p>

    <div class="info-box">
        <h3>📡 Your Network</h3>
        <p>
            IP Address: {{ my_network.ip_address or 'Not connected' }} &nbsp;|&nbsp;
            Subnet Mask: {{ my_network.subnet_mask or '-' }} &nbsp;|&nbsp;
            Gateway: {{ my_network.gateway or '-' }} &nbsp;|&nbsp;
            DNS: {{ my_network.dns or '-' }}
        </p>
    </div>

    {% if suspicious %}
    <div class="warning-box">
        <h3>⚠ Possible Rogue AP / Evil Twin Detected</h3>
        {% for ssid, bssids in suspicious.items() %}
            <p><strong>{{ ssid }}</strong> is broadcasting from multiple BSSIDs with different security settings: {{ bssids | join(', ') }}</p>
        {% endfor %}
    </div>
    {% endif %}

    <table>
        <tr>
            <th>SSID</th>
            <th>Authentication</th>
            <th>Encryption</th>
            <th>Best Signal</th>
            <th>Risk</th>
            <th>Reason</th>
            <th>First Seen</th>
        </tr>
        {% for net in networks %}
        <tr>
            <td>{{ net.ssid }}{% if net.is_new %}<span class="new-badge">NEW</span>{% endif %}</td>
            <td>{{ net.auth or '-' }}</td>
            <td>{{ net.encryption or '-' }}</td>
            <td>{{ net.best_signal }}%</td>
            <td class="{{ net.risk }}">{{ net.risk }}</td>
            <td>{{ net.reason }}</td>
            <td>{{ net.first_seen or '-' }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def dashboard():
    raw = run_netsh_scan()
    networks = parse_networks(raw)
    my_network = get_network_info()

    new_bssids = record_scan(networks)
    suspicious = detect_duplicate_ssids(networks)

    enriched = []
    for net in networks:
        risk, reason = score_network(net)
        signals = [b["signal"] for b in net["bssids"] if b["signal"] is not None]
        best_signal = max(signals) if signals else 0

        net_bssids = [b["bssid"] for b in net["bssids"]]
        is_new = any(b in new_bssids for b in net_bssids)

        first_seen_dates = [get_first_seen(b) for b in net_bssids if get_first_seen(b)]
        first_seen = min(first_seen_dates) if first_seen_dates else None

        enriched.append({
            "ssid": net["ssid"],
            "auth": net["auth"],
            "encryption": net["encryption"],
            "best_signal": best_signal,
            "risk": risk,
            "reason": reason,
            "is_new": is_new,
            "first_seen": first_seen
        })

    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}
    enriched.sort(key=lambda n: risk_order.get(n["risk"], 4))

    return render_template_string(
        PAGE_TEMPLATE,
        networks=enriched,
        count=len(enriched),
        suspicious=suspicious,
        my_network=my_network
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)