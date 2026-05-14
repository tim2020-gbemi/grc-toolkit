# GRC Toolkit

Security automation scripts for GRC engineers and compliance analysts.
Built to reduce manual effort on control mapping, assessment tracking, and audit reporting.

---

## compliance_mapper.py

Maps NIST CSF 2.0 controls to ISO 27001:2022 and SOC 2 TSC equivalents.
Tracks assessment status per control. Exports audit-ready reports in CSV and HTML.

### What it does

- Cross-references controls across NIST CSF 2.0, ISO 27001:2022, and SOC 2 TSC
- Tracks compliance status per control (Compliant, Partial, Non-Compliant, Not Assessed)
- Calculates a live compliance score based on assessed controls
- Exports a styled HTML dashboard for audit presentations
- Exports a CSV report for spreadsheet-based workflows

### Run it

python compliance_mapper.py

### Commands

| Command | What it does |
|---|---|
| `list` | Show all controls in the database |
| `lookup <ID>` | Look up a control e.g. `lookup PR.AA-01` |
| `function <NAME>` | Filter controls by NIST function e.g. `function PROTECT` |
| `update <ID>` | Update a control's assessment status |
| `report` | Export CSV compliance report |
| `html` | Generate HTML compliance dashboard |

### Frameworks covered

| Framework | Version |
|---|---|
| NIST CSF | 2.0 |
| ISO 27001 | 2022 |
| SOC 2 | Trust Services Criteria |

---

## About

Built by a GRC engineer and cybersecurity analyst as part of a security automation toolkit.
Focus: reducing the manual overhead of compliance mapping and audit prep.

Tools used: Python 3, GitHub Copilot, VS Code.

---

## Roadmap

- [ ] Vulnerability tracker with CVE to asset mapping
- [ ] Risk scoring engine (likelihood x impact)
