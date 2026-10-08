# FraudX Sentinel User Guide

FraudX Sentinel is a local fraud intelligence SOC workspace. It stores only analyst-submitted or approved imported telemetry in the local SQLite database.

## Start The Project

Run backend:

```powershell
cd "C:\Users\654000\Desktop\CyberSecurityProjects\FraudX-Sentinel"
.\start-backend.ps1
```

Run frontend in a second terminal:

```powershell
cd "C:\Users\654000\Desktop\CyberSecurityProjects\FraudX-Sentinel"
.\start-frontend.ps1
```

Optional two-terminal launcher:

```powershell
.\start-project.ps1
```

Open `http://localhost:5173`.

## First Access

The first account becomes the local administrator. After the first account exists, the app shows the sign-in screen and blocks duplicate initial setup.

Passwords must be at least 12 characters. Sessions expire after 12 hours or when the user signs out.

## Analyst Workflow

1. Open Command Center.
2. Add a verified event manually or import JSON/CSV.
3. Detection rules evaluate the event.
4. Matching events create alerts, incidents, entities, indicators, and relationships.
5. Triage alerts from Alert Queue.
6. Open Incidents to assign ownership, set SLA due time, add notes, register evidence, and download a report.
7. Use Digital DNA and Investigations to review relationships and evidence links.

## Import Format

JSON accepts either an array:

```json
[
  {
    "event_type": "BOOKING_REQUEST",
    "user_id": "account-101",
    "device_id": "device-22",
    "source_ip": "10.0.0.15",
    "target": "booking-api",
    "risk_context": "Observed high request rate",
    "metadata": {}
  }
]
```

or an object:

```json
{ "events": [] }
```

CSV requires:

```text
event_type,user_id,device_id,source_ip,target,risk_context,amount,new_beneficiary
```

Required columns are `event_type`, `user_id`, `device_id`, and `source_ip`.

## Local Data Boundary

FraudX does not include live third-party feeds by default. The connector endpoint is closed until `INGEST_API_KEY` is set in `.env`.

## Reset Local Analyst Data

Admins can call `POST /api/environment/clear` to clear local investigation data. User accounts remain intact.
