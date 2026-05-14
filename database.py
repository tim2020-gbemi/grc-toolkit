# database.py
# Handles all database operations for the GRC Toolkit.
# Week 3 adds: users table, audit log table, user functions.

import sqlite3
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from compliance_mapper import CONTROLS_DB

DB_FILE = "grc.db"


def get_connection():
    """Open a connection to the database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create all tables if they don't exist.
    Populate controls and default users on first run.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Controls table (same as Week 2)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS controls (
            control_id       TEXT PRIMARY KEY,
            nist_function    TEXT,
            nist_description TEXT,
            iso_27001        TEXT,
            iso_description  TEXT,
            soc2_tsc         TEXT,
            soc2_description TEXT,
            status           TEXT DEFAULT 'Not Assessed'
        )
    """)

    # Users table
    # role is either 'admin' (can edit) or 'viewer' (read only)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT DEFAULT 'viewer'
        )
    """)

    # Audit log table
    # Every status change gets recorded here with who did it and when
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id  TEXT,
            old_status  TEXT,
            new_status  TEXT,
            changed_by  TEXT,
            changed_at  TEXT
        )
    """)

    # Populate controls if empty
    cursor.execute("SELECT COUNT(*) FROM controls")
    if cursor.fetchone()[0] == 0:
        print("Initialising database with controls...")
        for control_id, details in CONTROLS_DB.items():
            cursor.execute("""
                INSERT INTO controls (
                    control_id, nist_function, nist_description,
                    iso_27001, iso_description,
                    soc2_tsc, soc2_description, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                control_id,
                details["nist_function"],
                details["nist_description"],
                ", ".join(details["iso_27001"]),
                details["iso_description"],
                ", ".join(details["soc2_tsc"]),
                details["soc2_description"],
                details["status"]
            ))
        print(f"Loaded {len(CONTROLS_DB)} controls.")

    # Create default users if none exist
    # IMPORTANT: change these passwords after first login
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        print("Creating default users...")
        default_users = [
            ("admin",  "admin123",  "admin"),
            ("viewer", "viewer123", "viewer"),
        ]
        for username, password, role in default_users:
            # Never store plain text passwords. generate_password_hash encrypts them.
            hashed = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, hashed, role)
            )
        print("Default users created. Username: admin / Password: admin123")

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# CONTROL FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_all_controls():
    """Fetch all controls from the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM controls ORDER BY nist_function, control_id")
    rows = cursor.fetchall()
    conn.close()
    return rows


def update_status(control_id, new_status, changed_by):
    """
    Update a control's status and write to the audit log.
    changed_by = the username of whoever made the change.
    """
    valid_statuses = ["Compliant", "Partial", "Non-Compliant", "Not Assessed"]
    if new_status not in valid_statuses:
        return False

    conn = get_connection()
    cursor = conn.cursor()

    # Get the current status before changing it (for the audit log)
    cursor.execute("SELECT status FROM controls WHERE control_id = ?", (control_id,))
    row = cursor.fetchone()
    old_status = row["status"] if row else "Unknown"

    # Update the status
    cursor.execute(
        "UPDATE controls SET status = ? WHERE control_id = ?",
        (new_status, control_id)
    )

    # Write to audit log
    cursor.execute("""
        INSERT INTO audit_log (control_id, old_status, new_status, changed_by, changed_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        control_id,
        old_status,
        new_status,
        changed_by,
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()
    return True


def get_summary():
    """Count controls by status."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status, COUNT(*) as count FROM controls GROUP BY status")
    rows = cursor.fetchall()
    conn.close()
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    for row in rows:
        summary[row["status"]] = row["count"]
    return summary


def get_audit_log():
    """Fetch the last 20 audit log entries, newest first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM audit_log
        ORDER BY changed_at DESC
        LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# USER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_user_by_username(username):
    """Find a user by their username. Returns the row or None."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def verify_password(username, password):
    """
    Check if the username and password are correct.
    Returns the user row if valid, None if not.
    """
    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None
