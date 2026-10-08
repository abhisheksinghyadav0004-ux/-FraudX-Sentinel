# FraudX Sentinel

FraudX Sentinel is a local-first fraud intelligence and investigation workspace. It accepts analyst-verified events, applies enabled correlation rules, opens evidence-backed alerts and incidents, and keeps an audit trail of workflow actions.

## What Works

- Manual event intake plus JSON and CSV batch import
- Persistent SQLite storage for events, alerts, cases, entities, indicators, relationships, notes, rules, and audit logs
- Rule-based detection with persistent enable/disable controls
- Alert triage, incident containment workflow, and analyst notes
- Digital DNA relationship view and local intelligence records
- CSV exports for events, alerts, and incidents
- Structured incident report endpoint: `GET /api/incidents/{id}/report`
- Docker API deployment configuration and local unit tests

## Run Locally

Backend:

```powershell
cd "C:\Users\654000\Desktop\CyberSecurityProjects\FraudX-Sentinel"
.\start-backend.ps1
```

The launcher automatically stops only an existing FraudX backend on port `8000` before it starts a fresh reload server. It never requires a PID. If PowerShell blocks scripts in a new terminal, run this once for that terminal and then repeat the command above:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

Frontend:

```powershell
.\start-frontend.ps1
```

To launch both in separate terminals:

```powershell
.\start-project.ps1
```

Manual frontend command:

```powershell
cd "C:\Users\654000\Desktop\CyberSecurityProjects\FraudX-Sentinel\frontend"
npm run dev
```

Open `http://localhost:5173`.

On the first launch, FraudX asks you to create the local administrator account. No default username or password is included. The session expires after 12 hours or when you sign out.

## Import Format

JSON accepts an array of event objects, or `{ "events": [...] }`.

CSV requires these columns:

```text
event_type,user_id,device_id,source_ip,target,risk_context,amount,new_beneficiary
```

Only `event_type`, `user_id`, `device_id`, and `source_ip` are required. Use analyst-verified data only.

## Configuration

Copy `.env.example` to `.env` and restrict `ALLOWED_ORIGINS` before deploying.

The local SQLite database is intentionally excluded from Git. Back it up before upgrades or deployment changes.

## Connector Webhook

FraudX can accept normalized events from an approved log forwarder through `POST /api/connectors/events`.

1. Set a long random `INGEST_API_KEY` in `.env`.
2. Restart the backend.
3. Send `X-FraudX-Ingest-Key` with the request.
4. Use `{ "events": [...] }` with the same event shape as the JSON import format.

The webhook returns `503` while no ingest key is configured. It is intentionally closed by default and does not claim a live SIEM connection.

## Verification

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
cd frontend
npm run build
```

More documentation:

- `docs/USER_GUIDE.md`
- `docs/API_REFERENCE.md`
- `docs/ACCEPTANCE_CHECKLIST.md`

## Integration Boundary

No third-party intelligence or SIEM feeds are preconfigured. Add approved provider credentials and a dedicated connector only after validating legal, privacy, and operational requirements. The project deliberately does not claim live external intelligence without a real configured source.
