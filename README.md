# FraudX Sentinel

**FraudX Sentinel** is a local-first cyber fraud intelligence, detection, and response platform. It converts analyst-verified telemetry into evidence-backed alerts, incidents, threat entities, local indicators, Digital DNA relationships, audit logs, and investigation reports.

The project is designed as a controlled SOC-style workspace for demonstrating how fraud signals can move through a complete investigation lifecycle without relying on fake preloaded data or unverified external feeds.

![FraudX Sentinel Command Center](screenshots/command%20center(1).png)

## Project Summary

FraudX Sentinel focuses on explainable fraud detection. Instead of showing static dashboard numbers, the system starts from submitted telemetry. An analyst enters or imports verified events, the backend applies enabled detection rules, and the platform creates alerts and investigation records only when the evidence matches a rule.

This makes the workflow transparent:

```text
Verified Event -> Detection Rule -> Alert -> Incident -> Evidence -> Report
```

## Core Objectives

- Detect suspicious fraud patterns from local event telemetry.
- Maintain a clean evidence trail for every alert and incident.
- Avoid fake dashboard data and clearly separate real configured integrations from demo/manual intake.
- Provide a modern investigation workspace for alert triage, case handling, evidence registration, and reporting.
- Demonstrate how a production system could later connect to SIEM tools, payment systems, booking engines, log forwarders, or fraud APIs.

## Key Features

### Local-first analyst workspace

- Manual event intake from the Command Center.
- JSON and CSV batch import.
- Local SQLite storage.
- No hardcoded external intelligence feed.
- No pre-seeded fake investigation records.

### Rule-based fraud detection

FraudX Sentinel includes configurable detection rules for:

- High booking velocity.
- High-value transfer to a new beneficiary.
- Repeated failed login attempts.
- Brand impersonation or phishing-style URL events.
- MFA failure patterns.

Rules can be enabled or disabled from the Detection Rules section.

### Alert queue and triage

- Evidence-backed alert queue.
- Risk score and severity labels.
- Alert status workflow.
- Acknowledge and contain actions.
- Audit logging for analyst actions.

### Incident management

- Automatic incident creation from confirmed alerts.
- Incident status workflow.
- Case ownership assignment.
- SLA due time tracking.
- Analyst notes.
- Evidence register with SHA-256 validation.
- Structured JSON incident report download.

### Digital DNA graph

Digital DNA shows how a suspicious entity connects to:

- Source IP.
- Device identifier.
- Target resource.
- Incident.
- Evidence notes.
- Relationship confidence score.

This makes correlation explainable and reviewable.

### Local threat intelligence

The Threat Intelligence section stores local indicators observed from submitted evidence. These indicators are not claimed to be third-party threat feed records unless a real connector is configured.

### Access control

- First-run administrator setup.
- Secure local login.
- 12-hour session tokens.
- Admin user creation.
- Password visibility toggle for usability.
- Session logout.

### Audit trail

The platform records important actions such as sign-in, event intake, batch imports, alert updates, incident updates, notes, evidence registration, user creation, and environment clearing.

## Screenshots

| Section | Preview |
| --- | --- |
| Command Center | [View screenshot](screenshots/command%20center(1).png) |
| Alert Queue | [View screenshot](screenshots/Alert%20queue.png) |
| Incidents | [View screenshot](screenshots/Incidents(1).png) |
| Digital DNA | [View screenshot](screenshots/Digital%20DNA.png) |
| Threat Entities | [View screenshot](screenshots/Threat%20Entities.png) |
| Campaigns | [View screenshot](screenshots/Campaigns.png) |
| Threat Intelligence | [View screenshot](screenshots/Threat%20Intelligence.png) |
| Transactions | [View screenshot](screenshots/Transactions.png) |
| Identity | [View screenshot](screenshots/Identity.png) |
| Investigations | [View screenshot](screenshots/Investigations.png) |
| Detection Rules | [View screenshot](screenshots/Detection%20Rules.png) |
| Access Control | [View screenshot](screenshots/Access%20Control.png) |
| Audit Logs | [View screenshot](screenshots/Audit%20Logs.png) |

## Technology Stack

### Frontend

- React
- TypeScript
- Vite
- CSS custom design system
- Local API integration through `fetch`

### Backend

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Pydantic validation
- Uvicorn ASGI server

### DevOps and Project Support

- Dockerfile
- Docker Compose
- GitHub Actions verification workflow
- PowerShell start scripts
- Python unit tests
- Markdown documentation

## Project Architecture

```text
FraudX-Sentinel/
├── backend/
│   ├── main.py
│   ├── models.py
│   ├── detection.py
│   ├── database.py
│   ├── settings.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── App.css
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── docs/
│   ├── USER_GUIDE.md
│   ├── API_REFERENCE.md
│   └── ACCEPTANCE_CHECKLIST.md
├── screenshots/
├── tests/
├── .github/workflows/
├── start-backend.ps1
├── start-frontend.ps1
├── start-project.ps1
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## How The System Works

### 1. Analyst submits verified telemetry

The analyst can submit events from the Command Center. Supported event types include:

- `LOGIN`
- `BOOKING_REQUEST`
- `TRANSACTION`
- `URL_CLICK`
- `MFA`
- `DEVICE_REGISTERED`

### 2. Backend evaluates detection rules

Each event is checked against enabled rules. If a rule matches, the backend creates:

- Alert.
- Incident.
- Campaign.
- Threat entity.
- Local indicators.
- Relationship graph entries.
- Audit log entry.

### 3. Alert is reviewed

The analyst opens Alert Queue and performs triage:

- Review risk and evidence.
- Acknowledge alert.
- Contain alert.

### 4. Incident is investigated

The incident workspace supports:

- Start review.
- Contain case.
- Assign owner.
- Set SLA due time.
- Add analyst notes.
- Register evidence references and SHA-256 hashes.
- Download structured report.

### 5. Correlation becomes explainable

Digital DNA and Investigation sections show how the system connected the event, device, IP, target, entity, campaign, and incident.

## Demo Scenario

### Booking bot abuse detection

Submit the following event six times:

```text
Event type: BOOKING_REQUEST
Account: acct-101
Device: device-auto-01
Source IP: 10.10.1.25
Target: ticket-booking-api
Context: Multiple booking attempts observed from same device
```

Expected result:

- Events processed increases.
- A critical alert is created.
- A fraud incident is opened.
- Digital DNA shows relationships between device, IP, target, and incident.

### Payment fraud detection

Submit one transaction event:

```text
Event type: TRANSACTION
Account: acct-202
Device: device-payment-09
Source IP: 10.10.2.45
Target: upi-transfer-service
Context: High value transfer to newly added beneficiary
Amount: 75000
New beneficiary: true
```

Expected result:

- Payment fraud alert is created.
- Transaction appears in the Transactions section.
- Related incident and local intelligence records are generated.

## Installation And Local Setup

### Prerequisites

Install:

- Python 3.11 or newer
- Node.js 20 or newer
- Git
- PowerShell

### Clone the repository

```powershell
git clone https://github.com/abhisheksinghyadav0004-ux/-FraudX-Sentinel.git
cd -FraudX-Sentinel
```

### Create and activate Python virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
```

If PowerShell blocks script execution in the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

### Install frontend dependencies

```powershell
cd frontend
npm install
cd ..
```

## Running The Project

### Option 1: Start both backend and frontend

```powershell
.\start-project.ps1
```

This opens separate terminals for backend and frontend.

### Option 2: Start manually

Backend:

```powershell
.\start-backend.ps1
```

Frontend:

```powershell
.\start-frontend.ps1
```

Open:

```text
http://localhost:5173
```

Backend API:

```text
http://127.0.0.1:8000
```

Health check:

```text
http://127.0.0.1:8000/health
```

## First Login

On first launch, the system asks you to create the first local administrator account.

Important:

- No default username is shipped.
- No default password is shipped.
- The first account becomes administrator.
- After the first account exists, the app shows the sign-in screen.
- Sessions expire after 12 hours or when the user signs out.

## Import Format

### JSON

FraudX accepts either an array:

```json
[
  {
    "event_type": "BOOKING_REQUEST",
    "user_id": "acct-101",
    "device_id": "device-auto-01",
    "source_ip": "10.10.1.25",
    "target": "ticket-booking-api",
    "risk_context": "Multiple booking attempts observed from same device",
    "metadata": {}
  }
]
```

or an object:

```json
{
  "events": []
}
```

### CSV

Required columns:

```text
event_type,user_id,device_id,source_ip,target,risk_context,amount,new_beneficiary
```

Minimum required fields:

- `event_type`
- `user_id`
- `device_id`
- `source_ip`

## API Overview

Base URL:

```text
http://127.0.0.1:8000
```

Authenticated requests use:

```text
X-FraudX-Session: <session-token>
```

Important endpoints:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Backend health check |
| GET | `/api/auth/bootstrap` | Check if local users exist |
| POST | `/api/auth/register` | Create first administrator |
| POST | `/api/auth/login` | Login and receive session token |
| GET | `/api/dashboard` | Metrics and recent events |
| POST | `/api/events` | Submit one verified event |
| POST | `/api/events/batch` | Import event batch |
| GET | `/api/alerts` | List alerts |
| PATCH | `/api/alerts/{id}` | Update alert status |
| GET | `/api/incidents` | List incidents |
| PATCH | `/api/incidents/{id}` | Update incident status |
| GET | `/api/incidents/{id}/report` | Download structured incident report |
| GET | `/api/digital-dna` | Relationship graph data |
| GET | `/api/detection-rules` | Rule catalog |
| PATCH | `/api/detection-rules/{rule_id}` | Enable or disable rule |
| GET | `/api/audit-logs` | Audit trail |

Full API documentation is available in:

```text
docs/API_REFERENCE.md
```

## Connector Boundary

FraudX includes a secure connector endpoint:

```text
POST /api/connectors/events
```

It stays closed until an ingest key is configured.

Configure:

```text
INGEST_API_KEY=<long-random-secret>
```

Required request header:

```text
X-FraudX-Ingest-Key: <configured-ingest-key>
```

If no ingest key is configured, the endpoint returns `503`.

This design makes it clear that the current project does not falsely claim live SIEM, bank, payment gateway, or external threat-feed integration. Those can be added through the connector layer when approved credentials and real data sources are available.

## Configuration

Copy `.env.example` to `.env`:

```powershell
copy .env.example .env
```

Available settings:

| Variable | Description |
| --- | --- |
| `ENVIRONMENT` | Runtime environment label |
| `ALLOWED_ORIGINS` | Allowed frontend origins for CORS |
| `INGEST_API_KEY` | Secret key for external event ingestion |

The local SQLite database is excluded from Git.

## Testing And Verification

### Backend tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Frontend production build

```powershell
cd frontend
npm run build
```

### GitHub Actions

The repository includes a verification workflow:

```text
.github/workflows/verify.yml
```

It runs Python dependency installation, backend unit tests, Node dependency installation, and frontend production build.

## Security And Privacy Notes

- `.env` is ignored and must not be committed.
- SQLite database files are ignored.
- Python virtual environment is ignored.
- Node modules and frontend build output are ignored.
- External ingestion requires an explicit ingest key.
- Incident evidence stores references and hashes, not raw sensitive files.
- The platform is intended for controlled local demonstration and educational use unless production hardening is completed.

## Current Limitations

- External SIEM/payment/bank connectors are not preconfigured.
- The current deployment is local-first and not hardened for internet exposure.
- SQLite is used for local persistence; production deployments should use a managed database.
- Detection logic is rule-based; ML scoring can be added later.
- Role permissions are intentionally lightweight for project scope.

## Future Enhancements

- Real SIEM connector integration.
- Payment gateway webhook connector.
- Email/SMS fraud signal ingestion.
- Advanced graph visualization for Digital DNA.
- PDF incident report export.
- Multi-tenant organization support.
- Machine-learning risk scoring.
- Dockerized full-stack deployment profile.
- Extended RBAC with analyst, manager, and auditor roles.

## Documentation

Additional documentation:

- [User Guide](docs/USER_GUIDE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Acceptance Checklist](docs/ACCEPTANCE_CHECKLIST.md)

## Repository

GitHub:

```text
https://github.com/abhisheksinghyadav0004-ux/-FraudX-Sentinel
```

## Author

**Designed and Developed by Abhishek Yadav**

FraudX Sentinel was created as a cyber fraud intelligence and response project to demonstrate practical detection engineering, analyst workflow design, and evidence-backed investigation handling.
