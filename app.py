# app.py
# This is the Flask web server.
# It takes your compliance_mapper.py data and serves it in a browser.

from flask import Flask, render_template, request, redirect, url_for
from compliance_mapper import CONTROLS_DB

# Create the Flask app
# __name__ tells Flask where to find your templates and static files
app = Flask(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# A route is a URL. When someone visits that URL, Flask runs the function below it.
# ─────────────────────────────────────────────────────────────────────────────

# Route 1: Dashboard - the main page
# URL: http://localhost:5000/
@app.route("/")
def dashboard():
    # Count statuses for the summary cards
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    for details in CONTROLS_DB.values():
        summary[details["status"]] += 1

    total = len(CONTROLS_DB)

    # Calculate compliance score
    score = round((summary["Compliant"] / total) * 100) if total > 0 else 0

    # render_template loads dashboard.html from the templates/ folder
    # and passes the data into it
    return render_template(
        "dashboard.html",
        controls=CONTROLS_DB,
        summary=summary,
        score=score,
        total=total
    )


# Route 2: Update a control's status
# URL: http://localhost:5000/update
# This only accepts POST requests (form submissions), not direct URL visits
@app.route("/update", methods=["POST"])
def update_status():
    # Get the control ID and new status from the form
    control_id = request.form.get("control_id")
    new_status  = request.form.get("status")

    valid_statuses = ["Compliant", "Partial", "Non-Compliant", "Not Assessed"]

    # Update the status if the control exists and status is valid
    if control_id in CONTROLS_DB and new_status in valid_statuses:
        CONTROLS_DB[control_id]["status"] = new_status

    # Redirect back to the dashboard after updating
    return redirect(url_for("dashboard"))


# ─────────────────────────────────────────────────────────────────────────────
# RUN THE APP
# debug=True means Flask auto-reloads when you save changes. Handy for development.
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
