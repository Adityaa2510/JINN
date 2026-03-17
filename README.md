# SecOps AI Platform — Full Flask Edition

A production-ready, dual-mode cybersecurity platform merging:
- **Individual Mode** — Red Team AI with 8 offensive/recon tools
- **Organization Mode** — Enterprise SecOps with SIEM, assets, CVE tracking, and AI orchestration

Powered by **Gemini AI** (with smart fallback), **Flask + SQLAlchemy**, and a custom dual-mode UI.

---

## Project Structure

```
secops_platform/
├── app.py                          # Flask app — all routes, models, services, tools
├── requirements.txt
├── .env                            # Your secrets (create this)
│
├── templates/
│   ├── base.html                   # App shell (sidebar + topbar layout)
│   ├── login.html                  # Dark login page
│   ├── mode_selection.html         # Mode picker (Individual / Organization)
│   │
│   ├── individual/
│   │   ├── _nav.html               # Individual sidebar nav macro
│   │   ├── dashboard.html          # Stats + quick-launch + recent scans
│   │   ├── scan.html               # 8-tool scanner with console output
│   │   ├── chat.html               # AI Red Team chat (Gemini)
│   │   └── history.html            # Audit log + CSV export
│   │
│   ├── org/
│   │   ├── _nav.html               # Org sidebar nav macro
│   │   ├── dashboard.html          # SOC KPIs + live alerts + integration health
│   │   ├── alerts.html             # SIEM alert feed (filter + status update)
│   │   ├── assets.html             # Asset inventory table
│   │   ├── vulnerabilities.html    # CVE intelligence (NVD + KEV)
│   │   ├── patch.html              # Patch compliance queue
│   │   ├── integrations.html       # 6 enterprise tool cards
│   │   └── chat.html               # SOC Orchestration AI chat
│   │
│   └── admin/
│       └── users.html              # User management (admin only)
│
└── static/
    ├── css/styles.css              # Complete dual-mode stylesheet (Syne + JetBrains Mono)
    └── js/app.js                   # Chat engine, message formatter, sidebar
```

---

## Quick Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Create `.env` file
```
SECRET_KEY=your-random-secret-key-here
GEMINI_API_KEY=your-gemini-api-key-here   # Optional — app works without it
DATABASE_URL=sqlite:///secops_platform.db  # Or your PostgreSQL URL
```

### 3. Run
```bash
python app.py
```

Open http://localhost:5000

---

## Default Credentials

| Username  | Password          | Role    |
|-----------|-------------------|---------|
| `admin`   | `SecureAdmin123!` | Admin   |
| `analyst` | `Analyst123!`     | Analyst |

---

## Feature Summary

### Individual Mode (Red Team / Offensive)
| Feature           | Details                                                  |
|-------------------|----------------------------------------------------------|
| Dashboard         | Scan stats, quick-launch grid for all 8 tools            |
| Security Scanner  | Nmap, Nikto, Whois/DNS, OpenVAS, Shodan, theHarvester, Recon-ng, Google Dorks |
| AI Chat Console   | Gemini-powered Red Team AI with simulated offensive paths |
| Scan History      | Full audit log with CSV export                           |

### Organization Mode (Blue Team / SecOps)
| Feature              | Details                                                  |
|----------------------|----------------------------------------------------------|
| SOC Overview         | 4 KPIs + live alert feed + integration health panel      |
| SIEM Alerts          | Filter by source/severity/status, update status inline   |
| Asset Inventory      | 6 assets with hostname, IP, OS, criticality, department  |
| Vulnerability Data   | NVD CVEs with CVSS scores, KEV flags, filter + export    |
| Patch Compliance     | Priority queue (Immediate / 7-day / 30-day)              |
| Tool Integrations    | Splunk, CrowdStrike, Tenable, Sentinel, QRadar, ServiceNow |
| SOC Orchestration AI | Gemini-powered SOC analyst AI, messages saved to DB      |

### Shared / Admin
| Feature           | Details                                                  |
|-------------------|----------------------------------------------------------|
| CSV Exports       | Scan history, vulnerabilities, SIEM alerts               |
| User Management   | Create users, assign roles, enable/disable (admin only)  |
| Audit Logging     | Every scan logged to DB + security_audit.log file        |
| Session Mode      | Mode stored in DB + session, persists across refreshes   |

---

## AI Configuration

The app tries to call the Gemini API (`gemini-2.0-flash`) using your `GEMINI_API_KEY`.

If no key is set (or the call fails), it returns a realistic structured fallback response — so the app is **fully functional without a Gemini key**.

To get a free Gemini key: https://aistudio.google.com/app/apikey

---

## Security Notes

- Change `SECRET_KEY` before any deployment
- All scan targets are validated (IP/domain regex + shell injection prevention)
- Authorization checkbox is required before every scan
- Passwords are hashed with Werkzeug's `generate_password_hash`
- All scan activity is audit-logged per user
