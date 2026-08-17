# Wireless Security Network Analyzer

Scans nearby WiFi networks, scores their security risk, and displays results on a live web dashboard.

## Features
- Scans nearby networks (SSID, signal, auth/encryption type)
- Risk scoring (HIGH/MEDIUM/LOW) with reasons
- Scan history via SQLite — flags new networks
- Rogue AP / Evil Twin detection
- Own device network info (IP, gateway, DNS)
- Live auto-refreshing dashboard (Flask)

## Tech Stack
Python, Flask, SQLite, Windows `netsh`/`ipconfig`

## Setup
```bash
python -m venv venv
venv\Scripts\activate
pip install flask reportlab
python app.py
Open http://127.0.0.1:5000
Requires: Windows, Python 3.9+
Limitations
Uses OS-summary data (netsh), not raw packet capture — deauth detection and handshake analysis would require monitor mode, which isn't reliably supported on Windows WiFi drivers. A natural next step would be a Linux-based module for that.
Author
Krishna J — S7 EEE B