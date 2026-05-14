# app.py
# Flask web server for the GRC Toolkit.
# Now reads and writes from SQLite via database.py instead of memory.

from flask import Flask, render_template, request, redirect, url_for
from database import init_db, get_all_controls, update_status, get_summary

app = Flask(__name__)

# Initialise the database when the app starts
# Creates grc.db and loads controls if it doesn't exist yet
init_db()


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    # Pull live data from the database
    controls = get_all_controls()
    summary  = get_summary()
    total    = len(controls)
    score    = round((summary["Compliant"] / total) * 100) if total > 0 else 0

    return render_template(
        "dashboard.html",
        controls=controls,
        summary=summary,
        score=score,
        total=total
    )


@app.route("/update", methods=["POST"])
def update():
    control_id = request.form.get("control_id")
    new_status  = request.form.get("status")
    update_status(control_id, new_status)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
