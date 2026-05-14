# database.py
# Handles all database operations for the GRC Toolkit.
# SQLite is built into Python, no installation needed.
# It creates a file called grc.db in your project folder.

import sqlite3
from compliance_mapper import CONTROLS_DB

# The database file. SQLite creates this automatically on first run.
DB_FILE = "grc.db"


def get_connection():
    """
    Open a connection to the database.
    Think of this like opening a file before you can read or write to it.
    """
    conn = sqlite3.connect(DB_FILE)
    # This makes rows behave like dictionaries so you can access columns by name
    # e.g. row["control_id"] instead of row[0]
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Create the controls table if it doesn't exist yet.
    Then populate it with data from CONTROLS_DB if the table is empty.
    This runs once on first startup.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # CREATE TABLE IF NOT EXISTS means: only create it if it isn't already there
    # So running this multiple times won't break anything
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS controls (
            control_id    TEXT PRIMARY KEY,
            nist_function TEXT,
            nist_description TEXT,
            iso_27001     TEXT,
            iso_description TEXT,
            soc2_tsc      TEXT,
            soc2_description TEXT,
            status        TEXT DEFAULT 'Not Assessed'
        )
    """)

    # Check if the table already has data
    cursor.execute("SELECT COUNT(*) FROM controls")
    count = cursor.fetchone()[0]

    # Only insert data if the table is empty
    # This prevents duplicates every time the app restarts
    if count == 0:
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
        print(f"Loaded {len(CONTROLS_DB)} controls into database.")

    conn.commit()   # Save changes
    conn.close()    # Close the connection


def get_all_controls():
    """
    Fetch all controls from the database.
    Returns a list of rows, each row is like a dictionary.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM controls ORDER BY nist_function, control_id")
    rows = cursor.fetchall()
    conn.close()
    return rows


def update_status(control_id, new_status):
    """
    Update the status of a single control in the database.
    This change persists even after the app restarts.
    """
    valid_statuses = ["Compliant", "Partial", "Non-Compliant", "Not Assessed"]
    if new_status not in valid_statuses:
        return False

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE controls SET status = ? WHERE control_id = ?",
        (new_status, control_id)
    )
    conn.commit()
    conn.close()
    return True


def get_summary():
    """
    Count how many controls have each status.
    Returns a dictionary like: {"Compliant": 3, "Partial": 1, ...}
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT status, COUNT(*) as count
        FROM controls
        GROUP BY status
    """)
    rows = cursor.fetchall()
    conn.close()

    # Start with all statuses at 0 so missing ones don't cause errors
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    for row in rows:
        summary[row["status"]] = row["count"]

    return summary
