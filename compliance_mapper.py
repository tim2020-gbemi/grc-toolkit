"""
Compliance Control Cross-Reference Mapper
==========================================
Maps NIST CSF controls to ISO 27001 and SOC 2 equivalents.
Generates a compliance report you can share or extend.

Author: [Your Name]
Purpose: GRC Portfolio Project
Frameworks: NIST CSF 2.0, ISO 27001:2022, SOC 2 TSC
"""

import csv
import datetime


CONTROLS_DB = {
    "GV.OC-01": {
        "nist_function": "GOVERN",
        "nist_description": "Organizational mission, stakeholder expectations, and legal requirements are understood and documented.",
        "iso_27001": ["5.1", "5.2", "6.1.1"],
        "iso_description": "Leadership & organizational context",
        "soc2_tsc": ["CC1.1", "CC1.2"],
        "soc2_description": "Control Environment - Integrity & Ethical Values",
        "status": "Not Assessed",
    },
    "GV.RM-01": {
        "nist_function": "GOVERN",
        "nist_description": "Risk management objectives are established and agreed to by stakeholders.",
        "iso_27001": ["6.1.2", "6.1.3"],
        "iso_description": "Information security risk assessment & treatment",
        "soc2_tsc": ["CC3.1", "CC3.2"],
        "soc2_description": "Risk Assessment - Specifies Objectives",
        "status": "Not Assessed",
    },
    "ID.AM-01": {
        "nist_function": "IDENTIFY",
        "nist_description": "Inventories of hardware managed by the organization are maintained.",
        "iso_27001": ["8.1", "5.9"],
        "iso_description": "Inventory of information and other associated assets",
        "soc2_tsc": ["CC6.1"],
        "soc2_description": "Logical & Physical Access Controls",
        "status": "Not Assessed",
    },
    "ID.AM-02": {
        "nist_function": "IDENTIFY",
        "nist_description": "Inventories of software, services, and systems managed by the organization are maintained.",
        "iso_27001": ["8.1", "8.8"],
        "iso_description": "Asset inventory & management of technical vulnerabilities",
        "soc2_tsc": ["CC6.1", "CC7.1"],
        "soc2_description": "Logical Access & System Operations",
        "status": "Not Assessed",
    },
    "ID.RA-01": {
        "nist_function": "IDENTIFY",
        "nist_description": "Vulnerabilities in assets are identified, validated, and recorded.",
        "iso_27001": ["8.8", "6.1.2"],
        "iso_description": "Management of technical vulnerabilities & risk assessment",
        "soc2_tsc": ["CC3.2", "CC7.1"],
        "soc2_description": "Risk Assessment & System Operations",
        "status": "Not Assessed",
    },
    "PR.AA-01": {
        "nist_function": "PROTECT",
        "nist_description": "Identities and credentials for authorized users, services, and hardware are managed.",
        "iso_27001": ["5.15", "5.16", "5.17"],
        "iso_description": "Access control, identity management, authentication",
        "soc2_tsc": ["CC6.1", "CC6.2", "CC6.3"],
        "soc2_description": "Logical & Physical Access Controls",
        "status": "Not Assessed",
    },
    "PR.DS-01": {
        "nist_function": "PROTECT",
        "nist_description": "The confidentiality, integrity, and availability of data-at-rest are protected.",
        "iso_27001": ["8.24", "8.5"],
        "iso_description": "Use of cryptography & secure authentication",
        "soc2_tsc": ["CC6.1", "CC6.7"],
        "soc2_description": "Logical Access & Transmission Protections",
        "status": "Not Assessed",
    },
    "PR.DS-02": {
        "nist_function": "PROTECT",
        "nist_description": "The confidentiality, integrity, and availability of data-in-transit are protected.",
        "iso_27001": ["8.24", "8.20"],
        "iso_description": "Cryptography & network security controls",
        "soc2_tsc": ["CC6.7"],
        "soc2_description": "Transmission Integrity & Confidentiality",
        "status": "Not Assessed",
    },
    "DE.CM-01": {
        "nist_function": "DETECT",
        "nist_description": "Networks and network services are monitored to find potentially adverse events.",
        "iso_27001": ["8.16", "8.15"],
        "iso_description": "Monitoring activities & logging",
        "soc2_tsc": ["CC7.2", "CC7.3"],
        "soc2_description": "System Operations - Anomaly Detection",
        "status": "Not Assessed",
    },
    "DE.AE-02": {
        "nist_function": "DETECT",
        "nist_description": "Potentially adverse events are analyzed to better characterize them.",
        "iso_27001": ["8.16", "5.25"],
        "iso_description": "Monitoring & assessment of information security events",
        "soc2_tsc": ["CC7.3", "CC7.4"],
        "soc2_description": "Evaluation & Response to Security Events",
        "status": "Not Assessed",
    },
    "RS.MA-01": {
        "nist_function": "RESPOND",
        "nist_description": "The incident response plan is executed in coordination with relevant parties.",
        "iso_27001": ["5.26", "5.24"],
        "iso_description": "Response to information security incidents",
        "soc2_tsc": ["CC7.4", "CC7.5"],
        "soc2_description": "Incident Response & Recovery",
        "status": "Not Assessed",
    },
    "RS.CO-02": {
        "nist_function": "RESPOND",
        "nist_description": "Internal and external stakeholders are notified of incidents.",
        "iso_27001": ["5.26", "6.1.3"],
        "iso_description": "Incident response & disclosure obligations",
        "soc2_tsc": ["CC2.2", "CC7.4"],
        "soc2_description": "Communication & Incident Response",
        "status": "Not Assessed",
    },
    "RC.RP-01": {
        "nist_function": "RECOVER",
        "nist_description": "The recovery portion of the incident response plan is executed once initiated.",
        "iso_27001": ["5.29", "5.30"],
        "iso_description": "Information security during disruption & ICT readiness",
        "soc2_tsc": ["A1.2", "A1.3"],
        "soc2_description": "Availability - Recovery & Restoration",
        "status": "Not Assessed",
    },
}


def list_all_controls():
    print("\n" + "="*60)
    print("ALL CONTROLS IN DATABASE")
    print("="*60)
    functions = {}
    for control_id, details in CONTROLS_DB.items():
        func = details["nist_function"]
        if func not in functions:
            functions[func] = []
        functions[func].append(control_id)
    for func, controls in functions.items():
        print(f"\n[ {func} ]")
        for control_id in controls:
            desc = CONTROLS_DB[control_id]["nist_description"]
            print(f"  {control_id}: {desc[:60]}...")


def lookup_control(control_id):
    control_id = control_id.upper()
    if control_id not in CONTROLS_DB:
        print(f"\nControl '{control_id}' not found. Type 'list' to see all.")
        return
    c = CONTROLS_DB[control_id]
    print("\n" + "="*60)
    print(f"CONTROL: {control_id}")
    print("="*60)
    print(f"NIST Function : {c['nist_function']}")
    print(f"Description   : {c['nist_description']}")
    print(f"\nISO 27001     : {', '.join(c['iso_27001'])}")
    print(f"ISO Detail    : {c['iso_description']}")
    print(f"\nSOC 2 TSC     : {', '.join(c['soc2_tsc'])}")
    print(f"SOC 2 Detail  : {c['soc2_description']}")
    print(f"\nStatus        : {c['status']}")


def update_control_status(control_id, new_status):
    control_id = control_id.upper()
    valid_statuses = ["Not Assessed", "Compliant", "Partial", "Non-Compliant"]
    if control_id not in CONTROLS_DB:
        print(f"Control '{control_id}' not found.")
        return
    if new_status not in valid_statuses:
        print(f"Invalid status. Choose from: {', '.join(valid_statuses)}")
        return
    CONTROLS_DB[control_id]["status"] = new_status
    print(f"Updated {control_id} status to: {new_status}")


def generate_report():
    today = datetime.date.today().strftime("%Y-%m-%d")
    filename = f"compliance_report_{today}.csv"
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Control ID","NIST Function","NIST Description","ISO 27001 Controls","ISO 27001 Detail","SOC 2 TSC","SOC 2 Detail","Status"])
        for control_id, details in CONTROLS_DB.items():
            writer.writerow([control_id, details["nist_function"], details["nist_description"], ", ".join(details["iso_27001"]), details["iso_description"], ", ".join(details["soc2_tsc"]), details["soc2_description"], details["status"]])
            summary[details["status"]] += 1
    print(f"\nReport saved: {filename}")
    for status, count in summary.items():
        print(f"  {status}: {count} controls")


def show_by_function(nist_function):
    nist_function = nist_function.upper()
    valid_functions = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    if nist_function not in valid_functions:
        print(f"Invalid function. Choose from: {', '.join(valid_functions)}")
        return
    print(f"\n[ Controls under NIST CSF: {nist_function} ]")
    found = False
    for control_id, details in CONTROLS_DB.items():
        if details["nist_function"] == nist_function:
            found = True
            print(f"\n  {control_id}")
            print(f"  NIST : {details['nist_description']}")
            print(f"  ISO  : {', '.join(details['iso_27001'])} - {details['iso_description']}")
            print(f"  SOC2 : {', '.join(details['soc2_tsc'])} - {details['soc2_description']}")
            print(f"  Status: {details['status']}")
    if not found:
        print("No controls found for that function.")


def generate_html_report():
    """
    Generate a styled HTML compliance dashboard.
    Open the output file in any browser to view the report.
    """
    today = datetime.date.today().strftime("%Y-%m-%d")
    filename = f"compliance_dashboard_{today}.html"

    # Count statuses for summary cards
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}
    for details in CONTROLS_DB.values():
        summary[details["status"]] += 1

    total = len(CONTROLS_DB)
    score = round((summary["Compliant"] / total) * 100) if total > 0 else 0

    # Build table rows: one row per control
    table_rows = ""
    for control_id, details in CONTROLS_DB.items():
        status = details["status"]
        status_styles = {
            "Compliant":     "background:#1a6e3c;color:#a8f0c6",
            "Partial":       "background:#7a5c00;color:#ffe08a",
            "Non-Compliant": "background:#7a1e1e;color:#ffb3b3",
            "Not Assessed":  "background:#2a2a3d;color:#9999bb",
        }
        style = status_styles.get(status, "background:#2a2a3d;color:#9999bb")

        table_rows += f"""
        <tr>
            <td class="control-id">{control_id}</td>
            <td><span class="function-badge func-{details['nist_function'].lower()}">{details['nist_function']}</span></td>
            <td class="description">{details['nist_description']}</td>
            <td class="mapping">{', '.join(details['iso_27001'])}<br><small>{details['iso_description']}</small></td>
            <td class="mapping">{', '.join(details['soc2_tsc'])}<br><small>{details['soc2_description']}</small></td>
            <td><span class="status-badge" style="{style}">{status}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Compliance Dashboard - {today}</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg:#0d0d1a; --surface:#13131f; --border:#1e1e35;
            --accent:#4f8ef7; --text:#d0d0e8; --muted:#5a5a7a;
        }}
        * {{ box-sizing:border-box; margin:0; padding:0; }}
        body {{ background:var(--bg); color:var(--text); font-family:'IBM Plex Sans',sans-serif; font-size:14px; line-height:1.6; padding:40px 32px; }}
        .header {{ border-left:3px solid var(--accent); padding-left:20px; margin-bottom:40px; }}
        .header h1 {{ font-family:'IBM Plex Mono',monospace; font-size:22px; color:#fff; letter-spacing:.05em; }}
        .header p {{ color:var(--muted); font-size:12px; margin-top:4px; font-family:'IBM Plex Mono',monospace; }}
        .score-banner {{ display:flex; align-items:center; gap:20px; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px 28px; margin-bottom:32px; }}
        .score-number {{ font-family:'IBM Plex Mono',monospace; font-size:48px; font-weight:600; color:var(--accent); line-height:1; }}
        .score-label {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; }}
        .score-divider {{ width:1px; height:50px; background:var(--border); margin:0 8px; }}
        .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:40px; }}
        .card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px; text-align:center; }}
        .card .count {{ font-family:'IBM Plex Mono',monospace; font-size:32px; font-weight:600; line-height:1; margin-bottom:6px; }}
        .card .label {{ font-size:11px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); }}
        .card.compliant .count {{ color:#4cda8a; }}
        .card.partial .count {{ color:#f5c842; }}
        .card.noncomp .count {{ color:#f76f6f; }}
        .card.unassessed .count {{ color:var(--muted); }}
        .table-wrapper {{ overflow-x:auto; border:1px solid var(--border); border-radius:8px; }}
        table {{ width:100%; border-collapse:collapse; }}
        thead th {{ background:var(--surface); color:var(--muted); font-family:'IBM Plex Mono',monospace; font-size:11px; text-transform:uppercase; letter-spacing:.1em; padding:12px 16px; text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; }}
        tbody tr {{ border-bottom:1px solid var(--border); transition:background .15s; }}
        tbody tr:last-child {{ border-bottom:none; }}
        tbody tr:hover {{ background:rgba(79,142,247,.04); }}
        td {{ padding:12px 16px; vertical-align:top; }}
        td small {{ display:block; color:var(--muted); font-size:11px; margin-top:2px; }}
        .control-id {{ font-family:'IBM Plex Mono',monospace; font-size:12px; color:var(--accent); white-space:nowrap; }}
        .description {{ max-width:280px; font-size:13px; }}
        .mapping {{ font-family:'IBM Plex Mono',monospace; font-size:11px; white-space:nowrap; }}
        .function-badge {{ display:inline-block; padding:2px 8px; border-radius:3px; font-family:'IBM Plex Mono',monospace; font-size:10px; font-weight:600; letter-spacing:.05em; white-space:nowrap; }}
        .func-govern   {{ background:#1a2e5a; color:#7ab4ff; }}
        .func-identify {{ background:#1a3a2e; color:#7affd4; }}
        .func-protect  {{ background:#2e1a3a; color:#d4a0ff; }}
        .func-detect   {{ background:#3a2e1a; color:#ffd480; }}
        .func-respond  {{ background:#3a1a1a; color:#ff9e9e; }}
        .func-recover  {{ background:#1a3a3a; color:#80ffff; }}
        .status-badge {{ display:inline-block; padding:3px 10px; border-radius:3px; font-size:11px; font-family:'IBM Plex Mono',monospace; white-space:nowrap; }}
        .footer {{ margin-top:40px; padding-top:20px; border-top:1px solid var(--border); font-family:'IBM Plex Mono',monospace; font-size:11px; color:var(--muted); display:flex; justify-content:space-between; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>COMPLIANCE DASHBOARD</h1>
        <p>NIST CSF 2.0 &nbsp;/&nbsp; ISO 27001:2022 &nbsp;/&nbsp; SOC 2 TSC &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {today}</p>
    </div>
    <div class="score-banner">
        <div>
            <div class="score-number">{score}%</div>
            <div class="score-label">Compliance Score</div>
        </div>
        <div class="score-divider"></div>
        <div>
            <div style="font-size:13px;color:var(--muted);">Based on <strong style="color:var(--text)">{total}</strong> controls assessed across three frameworks.</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px;">Score counts only Compliant controls as passed.</div>
        </div>
    </div>
    <div class="cards">
        <div class="card compliant"><div class="count">{summary['Compliant']}</div><div class="label">Compliant</div></div>
        <div class="card partial"><div class="count">{summary['Partial']}</div><div class="label">Partial</div></div>
        <div class="card noncomp"><div class="count">{summary['Non-Compliant']}</div><div class="label">Non-Compliant</div></div>
        <div class="card unassessed"><div class="count">{summary['Not Assessed']}</div><div class="label">Not Assessed</div></div>
    </div>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>Control ID</th><th>Function</th><th>Description</th>
                    <th>ISO 27001</th><th>SOC 2 TSC</th><th>Status</th>
                </tr>
            </thead>
            <tbody>{table_rows}</tbody>
        </table>
    </div>
    <div class="footer">
        <span>grc-toolkit / compliance_mapper.py</span>
        <span>Report Date: {today}</span>
    </div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nHTML dashboard saved: {filename}")
    print("Open it in your browser to view the report.")


def main():
    print("\n" + "="*60)
    print("  COMPLIANCE CROSS-REFERENCE MAPPER")
    print("  NIST CSF 2.0 | ISO 27001:2022 | SOC 2 TSC")
    print("="*60)

    while True:
        print("\nCOMMANDS:")
        print("  list             - Show all controls")
        print("  lookup <ID>      - Look up a control  (e.g. lookup PR.AA-01)")
        print("  function <NAME>  - Filter by function (e.g. function PROTECT)")
        print("  update <ID>      - Update control status")
        print("  report           - Generate CSV report")
        print("  html             - Generate HTML dashboard report")
        print("  exit             - Quit")

        user_input = input("\n> ").strip()
        parts = user_input.split()
        if not parts:
            continue

        command = parts[0].lower()

        if command == "exit":
            print("Exiting. Good work.")
            break
        elif command == "list":
            list_all_controls()
        elif command == "lookup":
            if len(parts) < 2:
                print("Usage: lookup <CONTROL_ID>")
            else:
                lookup_control(parts[1])
        elif command == "function":
            if len(parts) < 2:
                print("Usage: function <NAME>  e.g. function PROTECT")
            else:
                show_by_function(parts[1])
        elif command == "update":
            if len(parts) < 2:
                print("Usage: update <CONTROL_ID>")
            else:
                print("Select new status:")
                print("  1. Compliant  2. Partial  3. Non-Compliant  4. Not Assessed")
                choice = input("Enter number: ").strip()
                status_map = {"1":"Compliant","2":"Partial","3":"Non-Compliant","4":"Not Assessed"}
                if choice in status_map:
                    update_control_status(parts[1], status_map[choice])
                else:
                    print("Invalid choice.")
        elif command == "report":
            generate_report()
        elif command == "html":
            generate_html_report()
        else:
            print(f"Unknown command: '{command}'.")


if __name__ == "__main__":
    main()
