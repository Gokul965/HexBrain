"""
HexBrain SQLite Database Schema and Initialization
Stores vulnerability classes, weaknesses, bug bounty programs, subdomains,
reports, CVEs, bypasses, and exploit payloads.
"""

import os
import sqlite3
import json

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hexbrain.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Classes
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS classes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        count INTEGER NOT NULL,
        bounty REAL DEFAULT 0,
        weaknesses_count INTEGER DEFAULT 0,
        weaknesses_json TEXT,
        data_json TEXT
    )
    ''')

    # Weaknesses
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS weaknesses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_id TEXT NOT NULL,
        name TEXT NOT NULL,
        count INTEGER NOT NULL,
        bounty REAL DEFAULT 0,
        tag TEXT,
        sev TEXT,
        FOREIGN KEY (class_id) REFERENCES classes(id)
    )
    ''')

    # Programs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS programs (
        name TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        bounty REAL DEFAULT 0,
        logo TEXT,
        tag TEXT,
        total_subdomains INTEGER DEFAULT 0,
        classes_json TEXT,
        by_class_json TEXT
    )
    ''')

    # Subdomains / Attack Surface
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_name TEXT NOT NULL,
        branch TEXT,
        domain TEXT NOT NULL,
        count INTEGER DEFAULT 1,
        FOREIGN KEY (program_name) REFERENCES programs(name)
    )
    ''')

    # Reports
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        program TEXT NOT NULL,
        severity TEXT,
        weakness TEXT NOT NULL,
        class_id TEXT,
        bounty REAL DEFAULT 0,
        votes INTEGER DEFAULT 0,
        reporter TEXT,
        disclosed_at TEXT,
        substate TEXT DEFAULT 'resolved',
        writeup TEXT,
        steps_to_reproduce TEXT,
        impact TEXT
    )
    ''')

    # CVEs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        cvss REAL DEFAULT 0.0,
        product TEXT,
        kev INTEGER DEFAULT 0,
        year INTEGER,
        month INTEGER,
        band INTEGER DEFAULT 0,
        epss REAL DEFAULT 0.0,
        likelihood REAL DEFAULT 0.0,
        description TEXT
    )
    ''')

    # Bypasses
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bypasses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        protection_type TEXT NOT NULL,
        vulnerability TEXT NOT NULL,
        technique TEXT NOT NULL,
        program TEXT,
        bounty REAL DEFAULT 0,
        report_id INTEGER,
        description TEXT,
        code_example TEXT
    )
    ''')

    # Payloads
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS payloads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        payload TEXT NOT NULL,
        description TEXT,
        variant TEXT
    )
    ''')

    # Indices for speed
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_class ON reports(class_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_weakness ON reports(weakness)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_weaknesses_class ON weaknesses(class_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_year ON cves(year)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bypasses_prot ON bypasses(protection_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_payloads_cat ON payloads(category)')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print('Database initialized successfully at', DB_PATH)
