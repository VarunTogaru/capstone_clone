import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "scans.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target TEXT,
            scan_type TEXT,
            command TEXT,
            result_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(target: str, scan_type: str, command: str, result_dict: dict) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()
    cursor.execute('''
        INSERT INTO scans (timestamp, target, scan_type, command, result_json)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, target, scan_type, command, json.dumps(result_dict)))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_scan_history() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, target, scan_type, command 
        FROM scans 
        ORDER BY id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": row[0],
            "timestamp": row[1],
            "target": row[2],
            "scan_type": row[3],
            "command": row[4]
        }
        for row in rows
    ]

def get_scan_result(scan_id: int) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT target, scan_type, command, result_json 
        FROM scans 
        WHERE id = ?
    ''', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return None
        
    return {
        "target": row[0],
        "scan_type": row[1],
        "command": row[2],
        **(json.loads(row[3]))
    }
