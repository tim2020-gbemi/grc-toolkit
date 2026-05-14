"""
Compliance Control Cross-Reference Mapper
==========================================
Maps NIST CSF controls to ISO 27001 and SOC 2 equivalents.
Generates a simple compliance report you can share or extend.

Author: Oluwatimilehin Oluwagbemi
Purpose: GRC Portfolio Project
Frameworks: NIST CSF 2.0, ISO 27001:2022, SOC 2 TSC
"""

import csv
import datetime


# ─────────────────────────────────────────────────────────────────────────────
# THE CONTROL DATABASE
# This is a Python dictionary. Think of it like a lookup table.
# Key   = NIST CSF Control ID
# Value = Details about that control and its mappings
# ─────────────────────────────────────────────────────────────────────────────

CONTROLS_DB = {
    "GV.OC-01": {
        "nist_function": "GOVERN",
        "nist_description": "Organizational mission, stakeholder expectations, and legal requirements are understood and documented.",
        "iso_27001": ["5.1", "5.2", "6.1.1"],
        "iso_description": "Leadership & organizational context",
        "soc2_tsc": ["CC1.1", "CC1.2"],
        "soc2_description": "Control Environment - Integrity & Ethical Values",
        "status": "Not Assessed",   # You will change this when you run assessments
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


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTIONS
# Functions are reusable blocks of code. def = define a function.
# ─────────────────────────────────────────────────────────────────────────────

def list_all_controls():
    """Print all controls in the database with their NIST function."""
    print("\n" + "="*60)
    print("ALL CONTROLS IN DATABASE")
    print("="*60)

    # Group controls by NIST function for cleaner output
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
            # Only show first 60 characters so the list stays readable
            print(f"  {control_id}: {desc[:60]}...")


def lookup_control(control_id):
    """
    Look up a single control and print all its cross-references.
    control_id = the NIST CSF ID like 'PR.AA-01'
    """
    # .upper() converts input to uppercase so 'pr.aa-01' still works
    control_id = control_id.upper()

    if control_id not in CONTROLS_DB:
        print(f"\nControl '{control_id}' not found in database.")
        print("Type 'list' to see all available controls.")
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
    """
    Update the assessment status of a control.
    Valid statuses: Not Assessed, Compliant, Partial, Non-Compliant
    """
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
    """
    Generate a CSV compliance report with all controls and their mappings.
    Saves to a file with today's date in the filename.
    """
    # Get today's date for the filename
    today = datetime.date.today().strftime("%Y-%m-%d")
    filename = f"compliance_report_{today}.csv"

    # Count statuses for the summary
    summary = {"Compliant": 0, "Partial": 0, "Non-Compliant": 0, "Not Assessed": 0}

    # Open the file and write to it
    # 'w' = write mode, newline='' prevents extra blank lines on Windows
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write the header row
        writer.writerow([
            "Control ID",
            "NIST Function",
            "NIST Description",
            "ISO 27001 Controls",
            "ISO 27001 Detail",
            "SOC 2 TSC",
            "SOC 2 Detail",
            "Status"
        ])

        # Write one row per control
        for control_id, details in CONTROLS_DB.items():
            writer.writerow([
                control_id,
                details["nist_function"],
                details["nist_description"],
                ", ".join(details["iso_27001"]),
                details["iso_description"],
                ", ".join(details["soc2_tsc"]),
                details["soc2_description"],
                details["status"]
            ])
            summary[details["status"]] += 1

    print(f"\nReport saved: {filename}")
    print("\nSUMMARY:")
    for status, count in summary.items():
        print(f"  {status}: {count} controls")


def show_by_function(nist_function):
    """Filter and show controls by NIST CSF function."""
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


# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# This is what runs when you execute the script.
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  COMPLIANCE CROSS-REFERENCE MAPPER")
    print("  NIST CSF 2.0 | ISO 27001:2022 | SOC 2 TSC")
    print("="*60)

    # This loop keeps the program running until you type 'exit'
    while True:
        print("\nCOMMANDS:")
        print("  list             - Show all controls")
        print("  lookup <ID>      - Look up a control  (e.g. lookup PR.AA-01)")
        print("  function <NAME>  - Filter by function (e.g. function PROTECT)")
        print("  update <ID>      - Update control status")
        print("  report           - Generate CSV report")
        print("  exit             - Quit")

        # Get user input and strip extra spaces
        user_input = input("\n> ").strip()

        # Split input into parts: 'lookup PR.AA-01' becomes ['lookup', 'PR.AA-01']
        parts = user_input.split()

        if not parts:
            continue  # If user just hits Enter, loop again

        command = parts[0].lower()

        if command == "exit":
            print("Exiting. Good work.")
            break

        elif command == "list":
            list_all_controls()

        elif command == "lookup":
            if len(parts) < 2:
                print("Usage: lookup <CONTROL_ID>  e.g. lookup PR.AA-01")
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
                print("  1. Compliant")
                print("  2. Partial")
                print("  3. Non-Compliant")
                print("  4. Not Assessed")
                choice = input("Enter number: ").strip()
                status_map = {
                    "1": "Compliant",
                    "2": "Partial",
                    "3": "Non-Compliant",
                    "4": "Not Assessed"
                }
                if choice in status_map:
                    update_control_status(parts[1], status_map[choice])
                else:
                    print("Invalid choice.")

        elif command == "report":
            generate_report()

        else:
            print(f"Unknown command: '{command}'. See commands above.")


# This line means: only run main() if this file is run directly.
# If another script imports this file, main() won't auto-run.
if __name__ == "__main__":
    main()
