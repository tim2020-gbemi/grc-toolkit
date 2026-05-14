# app.py
# Flask web server with login, logout, roles, and audit logging.

from flask import Flask, render_template, request, redirect, url_for, session, flash
from database import init_db, get_all_controls, update_status, get_summary, get_audit_log, verify_password

app = Flask(__name__)

# Secret key is used to encrypt session cookies
# In production you would use a long random string stored in an environment variable
app.secret_key = "grc-toolkit-secret-key-change-in-production"

# Initialise database on startup
init_db()


# ─────────────────────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────────────────────

def logged_in():
    """Check if a user is currently logged in."""
    return "username" in session

def is_admin():
    """Check if the current user is an admin."""
    return session.get("role") == "admin"


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    # If already logged in, go straight to dashboard
    if logged_in():
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # verify_password checks the hash in the database
        user = verify_password(username, password)

        if user:
            # Store username and role in the session cookie
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    # Clear the session, user is logged out
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    # Block access if not logged in
    if not logged_in():
        return redirect(url_for("login"))

    controls  = get_all_controls()
    summary   = get_summary()
    audit_log = get_audit_log()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0

    return render_template(
        "dashboard.html",
        controls=controls,
        summary=summary,
        audit_log=audit_log,
        score=score,
        total=total,
        username=session["username"],
        role=session["role"]
    )


@app.route("/update", methods=["POST"])
def update():
    # Block access if not logged in
    if not logged_in():
        return redirect(url_for("login"))

    # Only admins can change statuses
    if not is_admin():
        return redirect(url_for("dashboard"))

    control_id = request.form.get("control_id")
    new_status  = request.form.get("status")

    # Pass the username so the audit log knows who made the change
    update_status(control_id, new_status, session["username"])

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
