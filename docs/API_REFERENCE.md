# FraudX Sentinel API Reference

Base URL: `http://127.0.0.1:8000`

Authenticated requests require:

```text
X-FraudX-Session: <session-token>
```

## Public Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Backend health check |
| GET | `/api/auth/bootstrap` | Returns whether a local account already exists |
| POST | `/api/auth/register` | Creates the first administrator only |
| POST | `/api/auth/login` | Issues a 12-hour local session token |

## Workspace Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/dashboard` | Metrics, severity distribution, recent events |
| POST | `/api/events` | Ingest one analyst-verified event |
| POST | `/api/events/batch` | Ingest JSON event batch |
| GET | `/api/alerts` | Evidence-backed alerts |
| PATCH | `/api/alerts/{id}` | Update alert status |
| GET | `/api/incidents` | Investigation cases |
| PATCH | `/api/incidents/{id}` | Update incident status |
| GET | `/api/incidents/{id}/report` | Structured incident report |
| GET | `/api/incidents/{id}/notes` | Incident note timeline |
| POST | `/api/incidents/{id}/notes` | Add analyst note |
| GET | `/api/incidents/{id}/evidence` | Registered evidence items |
| POST | `/api/incidents/{id}/evidence` | Register evidence reference and SHA-256 |
| PATCH | `/api/incidents/{id}/assignment` | Assign owner and SLA due time |
| GET | `/api/entities` | Threat entities derived from local evidence |
| GET | `/api/campaigns` | Correlated campaigns |
| GET | `/api/intelligence` | Local indicators |
| GET | `/api/digital-dna` | Relationship graph data |
| GET | `/api/investigations/summary` | Investigation summary |
| GET | `/api/detection-rules` | Detection rule catalog |
| PATCH | `/api/detection-rules/{rule_id}` | Enable or disable a rule |
| GET | `/api/audit-logs` | Audit trail |
| GET | `/api/export/{resource}` | CSV export for events, alerts, or incidents |

## Admin Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/users` | List local users |
| POST | `/api/users` | Create analyst/admin user |
| POST | `/api/environment/clear` | Clear local analyst data |
| GET | `/api/connectors/status` | Ingestion connector status |

## Connector Endpoint

`POST /api/connectors/events` accepts normalized event batches only when `INGEST_API_KEY` is configured.

Required header:

```text
X-FraudX-Ingest-Key: <configured-ingest-key>
```

When no key is configured, the endpoint returns `503`.
