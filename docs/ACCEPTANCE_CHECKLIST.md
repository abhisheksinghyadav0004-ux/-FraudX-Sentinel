# FraudX Sentinel Acceptance Checklist

Use this checklist before screenshots, GitHub upload, or project submission.

## Runtime

- [ ] Backend starts with `.\start-backend.ps1`.
- [ ] Frontend starts with `.\start-frontend.ps1`.
- [ ] `http://127.0.0.1:8000/health` returns `healthy`.
- [ ] `http://localhost:5173` opens the workspace.

## Authentication

- [ ] First run allows one administrator account.
- [ ] Existing users see the sign-in screen.
- [ ] Duplicate administrator setup is blocked.
- [ ] Sign-out removes the session.

## Core Workflow

- [ ] Manual event intake accepts verified local telemetry.
- [ ] JSON/CSV import accepts approved event exports.
- [ ] Detection rules create alerts only from submitted evidence.
- [ ] Alert actions update status and audit logs.
- [ ] Incidents support status updates, owner assignment, SLA due time, notes, and evidence registration.
- [ ] Reports download as structured JSON.
- [ ] Digital DNA and Investigations show local correlation data.

## Integrity

- [ ] No hardcoded sample incidents or fake external intelligence are displayed.
- [ ] Empty states explain that analyst telemetry is required.
- [ ] Local SQLite database is excluded from Git.
- [ ] `.env` is excluded from Git.
- [ ] `.env.example` documents required settings.

## Verification

- [ ] Backend tests pass with `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.
- [ ] Frontend production build passes with `npm run build`.
- [ ] README run instructions are current.
