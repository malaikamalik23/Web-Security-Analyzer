import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.db")


def init_db():
    """Creates the scans table if it doesn't already exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            scan_date TEXT NOT NULL,
            findings_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(url, score, findings):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "INSERT INTO scans (url, score, scan_date, findings_json) VALUES (?, ?, ?, ?)",
        (url, score, datetime.now().strftime("%Y-%m-%d %H:%M"), json.dumps(findings))
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def get_all_scans():
    """Returns all past scans, most recent first."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    conn.close()

    scans = []
    for row in rows:
        scans.append({
            "id": row["id"],
            "url": row["url"],
            "score": row["score"],
            "scan_date": row["scan_date"],
            "findings": json.loads(row["findings_json"]),
        })
    return scans


def get_scan_by_id(scan_id):
    """Returns one specific past scan by its id, or None if not found."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()

    if row is None:
        return None
    return {
        "id": row["id"],
        "url": row["url"],
        "score": row["score"],
        "scan_date": row["scan_date"],
        "findings": json.loads(row["findings_json"]),
    }

def get_previous_scan(url, exclude_id=None):
    """Returns the most recent past scan for this URL, excluding the just-created one if given."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if exclude_id:
        row = conn.execute(
            "SELECT * FROM scans WHERE url = ? AND id != ? ORDER BY id DESC LIMIT 1",
            (url, exclude_id)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM scans WHERE url = ? ORDER BY id DESC LIMIT 1",
            (url,)
        ).fetchone()
    conn.close()

    if row is None:
        return None
    return {"id": row["id"], "url": row["url"], "score": row["score"], "scan_date": row["scan_date"]}