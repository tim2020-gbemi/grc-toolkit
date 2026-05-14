# app.py
# Flask web server for the GRC Toolkit.
# Week 4 adds: PDF export route.

import datetime
from flask import Flask, render_template, request, redirect, url_for, session, make_response
from xhtml2pdf import pisa
import io
from database import init_db, get_all_controls, update_status, get_summary, get_audit_log, verify_password

app = Flask(__name__)
app.secret_key = "grc-toolkit-secret-key-change-in-production"

init_db()


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def logged_in():
    return "username" in session

def is_admin():
    return session.get("role") == "admin"


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = verify_password(username, password)
        if user:
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
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
    if not logged_in():
        return redirect(url_for("login"))
    if not is_admin():
        return redirect(url_for("dashboard"))
    control_id = request.form.get("control_id")
    new_status  = request.form.get("status")
    update_status(control_id, new_status, session["username"])
    return redirect(url_for("dashboard"))


@app.route("/pdf")
def export_pdf():
    """
    Generate a PDF compliance report and return it as a download.
    Only logged-in users can access this.
    """
    if not logged_in():
        return redirect(url_for("login"))

    # Gather all the data we need for the report
    controls  = get_all_controls()
    summary   = get_summary()
    audit_log = get_audit_log()
    total     = len(controls)
    score     = round((summary["Compliant"] / total) * 100) if total > 0 else 0
    date      = datetime.date.today().strftime("%Y-%m-%d")

    # Render report.html to an HTML string with all the data filled in
    html_string = render_template(
        "report.html",
        controls=controls,
        summary=summary,
        audit_log=audit_log,
        score=score,
        total=total,
        date=date,
        username=session["username"]
    )

    # WeasyPrint converts the HTML string into a PDF binary
    pdf_buffer = io.BytesIO()
    pisa.CreatePDF(html_string, dest=pdf_buffer)
    pdf_bytes = pdf_buffer.getvalue()

    # Build the filename with today's date
    filename = f"compliance_report_{date}.pdf"

    # Create a response that tells the browser to download the file
    response = make_response(pdf_bytes)
    response.headers["Content-Type"]        = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"

    return response


if __name__ == "__main__":
    app.run(debug=True)
