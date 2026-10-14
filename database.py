"""
Wireless Security Network Analyzer - Database Layer
Stores scan history in SQLite and detects new/rogue networks.
"""

import sqlite3
from datetime import datetime

DB_FILE = "scan_history.db"

def init_db():
    """Creates the database and tables if they don't already exist."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS seen_networks (
            bssid TEXT PRIMARY KEY,
            ssid TEXT,
            auth TEXT,
            encryption TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)
    conn.commit()
    conn.close()

def record_scan(networks):
    """
    Takes the parsed networks list and updates the database:
    new BSSIDs get inserted, known ones get last_seen updated.
    Returns a list of BSSIDs that are new in this scan.
    """
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    now = datetime.now().isoformat(timespec="seconds")
    new_bssids = []

    for net in networks:
        for b in net["bssids"]:
            bssid = b["bssid"]
            cur.execute("SELECT bssid FROM seen_networks WHERE bssid = ?", (bssid,))
            exists = cur.fetchone()

            if exists:
                cur.execute(
                    "UPDATE seen_networks SET last_seen = ? WHERE bssid = ?",
                    (now, bssid)
                )
            else:
                cur.execute(
                    "INSERT INTO seen_networks (bssid, ssid, auth, encryption, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (bssid, net["ssid"], net["auth"], net["encryption"], now, now)
                )
                new_bssids.append(bssid)

    conn.commit()
    conn.close()
    return new_bssids

def get_first_seen(bssid):
    """Returns the first_seen timestamp for a given BSSID, or None."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT first_seen FROM seen_networks WHERE bssid = ?", (bssid,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def detect_duplicate_ssids(networks):
    """
    Flags possible rogue/evil-twin APs: same SSID name appearing in
    multiple SSID blocks with different auth/encryption settings.
    Returns a dict: {ssid: [list of bssids]}
    """
    suspicious = {}
    ssid_map = {}

    for net in networks:
        ssid_map.setdefault(net["ssid"], []).append(net)

    for ssid, entries in ssid_map.items():
        if len(entries) <= 1:
            continue
        auths = set(e["auth"] for e in entries)
        if len(auths) > 1:
            all_bssids = [b["bssid"] for e in entries for b in e["bssids"]]
            suspicious[ssid] = all_bssids

    return suspicious