import json
import uuid
import csv
import io
import hashlib
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.database import Base, SessionLocal, engine, get_session
from backend.detection import alert_summary, detect_event
from backend.models import (
    Alert,
    AnalystNote,
    AuditLog,
    Campaign,
    DetectionRule,
    EvidenceItem,
    EntityRelationship,
    Incident,
    IncidentAssignment,
    IntelligenceIndicator,
    SecurityEvent,
    ThreatEntity,
    UserAccount,
    UserSession,
)
from backend.settings import settings

app = FastAPI(title="FraudX Sentinel API", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "X-FraudX-Session"])


@app.middleware("http")
async def security_headers(request, call_next):
    public_paths = {"/health", "/openapi.json", "/docs", "/redoc", "/api/auth/bootstrap", "/api/auth/register", "/api/auth/login", "/api/connectors/events"}
    if request.method != "OPTIONS" and request.url.path.startswith("/api") and request.url.path not in public_paths:
        with SessionLocal() as session:
            has_users = session.scalar(select(UserAccount.id).limit(1)) is not None
            token = request.headers.get("X-FraudX-Session", "")
            token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
            active_session = session.scalar(select(UserSession).where(UserSession.token_hash == token_hash, UserSession.expires_at > datetime.now(timezone.utc)))
            user = session.get(UserAccount, active_session.user_id) if active_session else None
            if has_users and not user:
                return JSONResponse({"detail": "Authentication required"}, status_code=401)
            request.state.user = user
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


class EventInput(BaseModel):
    event_type: str = Field(max_length=32)
    user_id: str = Field(max_length=80)
    device_id: str = Field(max_length=80)
    source_ip: str = Field(max_length=64)
    target: str = Field(default="", max_length=180)
    metadata: dict = Field(default_factory=dict)
    risk_context: str = Field(default="", max_length=500)


class AlertAction(BaseModel):
    status: str = Field(pattern="^(ACKNOWLEDGED|INVESTIGATING|CONTAINED|RESOLVED|FALSE_POSITIVE)$")


class EventBatch(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=500)


class IncidentAction(BaseModel):
    status: str = Field(pattern="^(OPEN|INVESTIGATING|CONTAINED|RESOLVED)$")


class IncidentAssignmentInput(BaseModel):
    owner: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    due_at: datetime


class NoteInput(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    author: str = Field(default="Analyst", max_length=80)


class RuleAction(BaseModel):
    enabled: bool


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)

    @field_validator("username", mode="before")
    @classmethod
    def normalize_username(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value


class UserCreate(Credentials):
    role: str = Field(pattern="^(ADMIN|ANALYST)$")


class EvidenceInput(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    reference: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    source: str = Field(min_length=1, max_length=160)
    note: str = Field(default="", max_length=2000)


class ConnectorBatch(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=500)


def password_digest(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()


def issue_session(session: Session, user: UserAccount) -> str:
    token = secrets.token_urlsafe(32)
    session.add(UserSession(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=datetime.now(timezone.utc) + timedelta(hours=12)))
    return token


def serialize_user(user: UserAccount):
    return {"username": user.username, "role": user.role}


def require_admin(request: Request):
    user = getattr(request.state, "user", None)
    if not user or user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def require_ingest_key(request: Request):
    if not settings.ingest_api_key:
        raise HTTPException(status_code=503, detail="External ingestion is not configured")
    presented_key = request.headers.get("X-FraudX-Ingest-Key", "")
    if not secrets.compare_digest(presented_key, settings.ingest_api_key):
        raise HTTPException(status_code=401, detail="Invalid ingest key")


def serialize_event(event):
    return {"eventId": event.event_id, "timestamp": event.timestamp.isoformat(), "eventType": event.event_type, "userId": event.user_id, "deviceId": event.device_id, "sourceIp": event.source_ip, "target": event.target, "riskContext": event.risk_context}


def serialize_alert(alert):
    return {"id": alert.id, "alertId": alert.alert_id, "timestamp": alert.created_at.isoformat(), "severity": alert.severity, "riskScore": alert.risk_score, "category": alert.category, "affectedEntity": alert.affected_entity, "ruleName": alert.rule_name, "evidence": alert.evidence, "status": alert.status, "campaignId": alert.campaign_id or None}


def log(session, action, target, actor="system"):
    session.add(AuditLog(actor=actor, action=action, target=target))


def serialize_campaign(item):
    return {"campaignId": item.campaign_id, "title": item.title, "severity": item.severity, "status": item.status, "confidence": item.confidence, "summary": item.summary, "createdAt": item.created_at.isoformat(), "updatedAt": item.updated_at.isoformat()}


def serialize_incident(item, assignment=None):
    due_at = assignment.due_at if assignment else None
    if due_at and due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    sla_state = "UNSET"
    if due_at:
        sla_state = "MET" if item.status in {"CONTAINED", "RESOLVED"} else ("OVERDUE" if due_at < datetime.now(timezone.utc) else "ON_TRACK")
    return {"id": item.id, "incidentId": item.incident_id, "title": item.title, "severity": item.severity, "status": item.status, "campaignId": item.campaign_id, "owner": item.owner, "dueAt": due_at.isoformat() if due_at else None, "slaState": sla_state, "summary": item.summary, "createdAt": item.created_at.isoformat(), "updatedAt": item.updated_at.isoformat()}


def serialize_entity(item):
    return {"entityId": item.entity_id, "label": item.label, "entityType": item.entity_type, "riskScore": item.risk_score, "confidence": item.confidence, "disposition": item.disposition, "summary": item.summary, "firstSeen": item.first_seen.isoformat(), "lastSeen": item.last_seen.isoformat()}


def serialize_note(item):
    return {"id": item.id, "incidentId": item.incident_id, "author": item.author, "content": item.content, "createdAt": item.created_at.isoformat()}


def serialize_evidence(item):
    return {"id": item.id, "incidentId": item.incident_id, "title": item.title, "reference": item.reference, "sha256": item.sha256, "source": item.source, "note": item.note, "createdAt": item.created_at.isoformat()}


def correlate_alert(session, event, alert):
    """Persist evidence relationships from the event that generated a real alert."""
    campaign_id = f"CAMP-{uuid.uuid4().hex[:8].upper()}"
    entity_id = f"ENT-{uuid.uuid4().hex[:8].upper()}"
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    session.add(Campaign(campaign_id=campaign_id, title=f"{alert.category} investigation", severity=alert.severity, status="DETECTED", confidence=alert.risk_score, summary=f"Automatically opened from alert {alert.alert_id}; evidence is derived from local event {event.event_id}."))
    session.add(Incident(incident_id=incident_id, title=f"{alert.category}: {event.user_id}", severity=alert.severity, status="OPEN", campaign_id=campaign_id, owner="Unassigned", summary=f"Opened from rule {alert.rule_name}. Review source event {event.event_id} and attached evidence before disposition."))
    session.add(ThreatEntity(entity_id=entity_id, label=f"Observed entity: {event.device_id}", entity_type="DEVICE_CLUSTER", risk_score=alert.risk_score, confidence=alert.risk_score, disposition="ESCALATED", summary=f"Local correlation entity derived from event {event.event_id}."))
    for value, kind in [(event.source_ip, "IP_ADDRESS"), (event.device_id, "DEVICE_ID"), (event.target, "TARGET")]:
        if not value:
            continue
        indicator = session.scalar(select(IntelligenceIndicator).where(IntelligenceIndicator.value == value))
        if not indicator:
            indicator = IntelligenceIndicator(indicator_id=f"IOC-{uuid.uuid4().hex[:8].upper()}", value=value, indicator_type=kind, risk_score=alert.risk_score, confidence=alert.risk_score, status="OBSERVED", source=f"Local event {event.event_id}")
            session.add(indicator)
            session.flush()
        session.add(EntityRelationship(relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}", source_id=entity_id, target_id=indicator.indicator_id, relation_type="OBSERVED_WITH", confidence=alert.risk_score, evidence=f"Observed in event {event.event_id}: {alert.evidence}", campaign_id=campaign_id))
    session.add(EntityRelationship(relationship_id=f"REL-{uuid.uuid4().hex[:8].upper()}", source_id=incident_id, target_id=entity_id, relation_type="INVESTIGATES", confidence=alert.risk_score, evidence=f"Incident opened from alert {alert.alert_id}.", campaign_id=campaign_id))
    return campaign_id


RULE_CATALOG = [
    ("RULE-BOOK-001", "High booking velocity", "Automation abuse", "CRITICAL", "Six or more booking requests from one device in the recent event window."),
    ("RULE-PAY-001", "New beneficiary high-value transfer", "Payment fraud", "HIGH", "Transaction amount is at least 50,000 and beneficiary is new."),
    ("RULE-AUTH-001", "Repeated failed logins", "Account takeover", "HIGH", "Four or more failed login events from a source IP."),
    ("RULE-PHISH-001", "Brand impersonation URL", "Phishing", "HIGH", "A URL-click event is tagged with brand-impersonation context."),
    ("RULE-MFA-001", "MFA failure", "Account takeover", "MEDIUM", "An MFA event contains a failed context marker."),
]


def ensure_detection_rules(session):
    for rule_id, name, category, severity, logic in RULE_CATALOG:
        if not session.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id)):
            session.add(DetectionRule(rule_id=rule_id, name=name, category=category, severity=severity, logic=logic))
    session.commit()


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        ensure_detection_rules(session)


@app.get("/api/auth/bootstrap")
def auth_bootstrap(session: Session = Depends(get_session)):
    return {"hasUsers": session.scalar(select(UserAccount.id).limit(1)) is not None}


@app.post("/api/auth/register")
def register_admin(payload: Credentials, session: Session = Depends(get_session)):
    if session.scalar(select(UserAccount.id).limit(1)) is not None:
        raise HTTPException(status_code=403, detail="Initial administrator already exists")
    salt = secrets.token_hex(16)
    user = UserAccount(username=payload.username.lower(), password_salt=salt, password_hash=password_digest(payload.password, salt), role="ADMIN")
    session.add(user)
    session.flush()
    token = issue_session(session, user)
    log(session, "Initial administrator registered", user.username, actor=user.username)
    session.commit()
    return {"token": token, "user": serialize_user(user)}


@app.post("/api/auth/login")
def login(payload: Credentials, session: Session = Depends(get_session)):
    user = session.scalar(select(UserAccount).where(UserAccount.username == payload.username.lower()))
    if not user or not secrets.compare_digest(user.password_hash, password_digest(payload.password, user.password_salt)):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = issue_session(session, user)
    log(session, "Signed in", user.username, actor=user.username)
    session.commit()
    return {"token": token, "user": serialize_user(user)}


@app.get("/api/auth/me")
def me(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"user": serialize_user(user)}


@app.post("/api/auth/logout")
def logout(request: Request, session: Session = Depends(get_session)):
    token = request.headers.get("X-FraudX-Session", "")
    if token:
        session.execute(delete(UserSession).where(UserSession.token_hash == hashlib.sha256(token.encode()).hexdigest()))
        session.commit()
    return {"ok": True}


@app.get("/api/users")
def users(request: Request, session: Session = Depends(get_session)):
    require_admin(request)
    items = session.scalars(select(UserAccount).order_by(UserAccount.created_at.asc())).all()
    return {"items": [{**serialize_user(item), "id": item.id, "createdAt": item.created_at.isoformat()} for item in items]}


@app.post("/api/users")
def create_user(payload: UserCreate, request: Request, session: Session = Depends(get_session)):
    admin = require_admin(request)
    if session.scalar(select(UserAccount).where(UserAccount.username == payload.username.lower())):
        raise HTTPException(status_code=409, detail="Username already exists")
    salt = secrets.token_hex(16)
    user = UserAccount(username=payload.username.lower(), password_salt=salt, password_hash=password_digest(payload.password, salt), role=payload.role)
    session.add(user)
    log(session, f"Created {payload.role.lower()} account", user.username, actor=admin.username)
    session.commit()
    return {"user": serialize_user(user)}


@app.get("/health")
def health():
    return {"status": "healthy", "service": "FraudX Sentinel", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/dashboard")
def dashboard(session: Session = Depends(get_session)):
    alerts = session.scalars(select(Alert).order_by(Alert.created_at.desc())).all()
    events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())).all()
    severity, categories = alert_summary(alerts)
    unique_entities = len({item.user_id for item in events} | {item.device_id for item in events} | {item.source_ip for item in events})
    return {
        "metrics": {"eventsProcessed": len(events), "activeAlerts": sum(item.status not in {"RESOLVED", "FALSE_POSITIVE"} for item in alerts), "criticalAlerts": severity.get("CRITICAL", 0), "highRiskIncidents": sum(item.severity in {"HIGH", "CRITICAL"} for item in alerts), "suspiciousEntities": unique_entities, "activeCampaigns": len({item.campaign_id for item in alerts if item.campaign_id}), "detectionRate": round((len(alerts) / len(events) * 100), 1) if events else 0.0},
        "severity": severity, "categories": categories,
        "alerts": [serialize_alert(item) for item in alerts[:8]],
        "events": [serialize_event(item) for item in events[:10]],
    }


@app.get("/api/alerts")
def alerts(session: Session = Depends(get_session)):
    return {"items": [serialize_alert(item) for item in session.scalars(select(Alert).order_by(Alert.created_at.desc())).all()]}


@app.post("/api/events")
def ingest_event(payload: EventInput, session: Session = Depends(get_session)):
    event = SecurityEvent(event_id=f"EVT-{uuid.uuid4().hex[:10].upper()}", event_type=payload.event_type.upper(), user_id=payload.user_id, device_id=payload.device_id, source_ip=payload.source_ip, target=payload.target, metadata_json=json.dumps(payload.metadata), risk_context=payload.risk_context)
    session.add(event)
    session.flush()
    recent = session.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(100)).all()
    enabled_rules = {item.rule_id for item in session.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all()}
    finding = detect_event(event, recent, enabled_rules)
    alert = None
    if finding:
        severity, score, category, rule, evidence = finding
        alert = Alert(alert_id=f"ALR-{uuid.uuid4().hex[:8].upper()}", severity=severity, risk_score=score, category=category, affected_entity=payload.user_id, rule_name=rule, evidence=evidence)
        session.add(alert)
        session.flush()
        alert.campaign_id = correlate_alert(session, event, alert)
    log(session, "Event ingested", event.event_id)
    session.commit()
    return {"event": serialize_event(event), "alert": serialize_alert(alert) if alert else None}


@app.post("/api/events/batch")
def ingest_event_batch(payload: EventBatch, request: Request, session: Session = Depends(get_session)):
    results = []
    for item in payload.events:
        results.append(ingest_event(item, session))
    actor = getattr(request.state, "user", None)
    log(session, "Batch event import completed", f"{len(results)} events", actor=actor.username if actor else "analyst")
    session.commit()
    return {"eventsAccepted": len(results), "alertsCreated": sum(item["alert"] is not None for item in results)}


@app.post("/api/connectors/events")
def ingest_connector_events(payload: ConnectorBatch, request: Request, session: Session = Depends(get_session)):
    require_ingest_key(request)
    results = [ingest_event(item, session) for item in payload.events]
    log(session, "Connector batch accepted", f"{len(results)} events", actor="connector")
    session.commit()
    return {"eventsAccepted": len(results), "alertsCreated": sum(item["alert"] is not None for item in results)}


@app.get("/api/connectors/status")
def connector_status(request: Request):
    require_admin(request)
    return {"webhookIngestion": "CONFIGURED" if settings.ingest_api_key else "NOT_CONFIGURED", "supportedFormat": "FraudX event batch JSON"}


@app.post("/api/environment/clear")
def clear_environment(request: Request, session: Session = Depends(get_session)):
    require_admin(request)
    for model in (EvidenceItem, AnalystNote, EntityRelationship, IntelligenceIndicator, ThreatEntity, Incident, Campaign, Alert, SecurityEvent, AuditLog):
        session.execute(delete(model))
    session.commit()
    return {"message": "Local environment cleared. No seeded or synthetic records remain."}


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, action: AlertAction, request: Request, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = action.status
    actor = getattr(request.state, "user", None)
    log(session, f"Alert status changed to {action.status}", alert.alert_id, actor=actor.username if actor else "analyst")
    session.commit()
    return {"alert": serialize_alert(alert)}


@app.get("/api/audit-logs")
def audit_logs(session: Session = Depends(get_session)):
    items = session.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100)).all()
    return {"items": [{"timestamp": item.timestamp.isoformat(), "actor": item.actor, "action": item.action, "target": item.target, "result": item.result} for item in items]}


@app.get("/api/export/{resource}")
def export_csv(resource: str, session: Session = Depends(get_session)):
    exporters = {
        "events": (select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()), ["event_id", "timestamp", "event_type", "user_id", "device_id", "source_ip", "target", "risk_context"]),
        "alerts": (select(Alert).order_by(Alert.created_at.desc()), ["alert_id", "created_at", "severity", "risk_score", "category", "affected_entity", "rule_name", "evidence", "status", "campaign_id"]),
        "incidents": (select(Incident).order_by(Incident.updated_at.desc()), ["incident_id", "title", "severity", "status", "campaign_id", "owner", "summary", "created_at"]),
    }
    if resource not in exporters:
        raise HTTPException(status_code=404, detail="Export resource not found")
    query, columns = exporters[resource]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(columns)
    for item in session.scalars(query).all():
        writer.writerow([getattr(item, column) for column in columns])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="fraudx-{resource}.csv"'})


@app.get("/api/incidents")
def incidents(session: Session = Depends(get_session)):
    assignments = {item.incident_id: item for item in session.scalars(select(IncidentAssignment)).all()}
    return {"items": [serialize_incident(item, assignments.get(item.incident_id)) for item in session.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()]}


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: int, action: IncidentAction, request: Request, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = action.status
    actor = getattr(request.state, "user", None)
    log(session, f"Incident status changed to {action.status}", incident.incident_id, actor=actor.username if actor else "analyst")
    session.commit()
    return {"incident": serialize_incident(incident)}


@app.get("/api/incidents/{incident_id}/assignment")
def get_incident_assignment(incident_id: int, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    assignment = session.scalar(select(IncidentAssignment).where(IncidentAssignment.incident_id == incident.incident_id))
    return {"incident": serialize_incident(incident, assignment)}


@app.patch("/api/incidents/{incident_id}/assignment")
def assign_incident(incident_id: int, payload: IncidentAssignmentInput, request: Request, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    actor = getattr(request.state, "user", None)
    if not actor:
        raise HTTPException(status_code=401, detail="Authentication required")
    owner = payload.owner.lower().strip()
    if actor.role != "ADMIN" and owner != actor.username:
        raise HTTPException(status_code=403, detail="Analysts can only assign cases to themselves")
    if not session.scalar(select(UserAccount).where(UserAccount.username == owner)):
        raise HTTPException(status_code=404, detail="Assigned user does not exist")
    due_at = payload.due_at
    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)
    if due_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="Due time must be in the future")
    assignment = session.scalar(select(IncidentAssignment).where(IncidentAssignment.incident_id == incident.incident_id))
    if assignment:
        assignment.due_at = due_at
    else:
        assignment = IncidentAssignment(incident_id=incident.incident_id, due_at=due_at)
        session.add(assignment)
    incident.owner = owner
    log(session, "Incident owner and due time updated", incident.incident_id, actor=actor.username)
    session.commit()
    return {"incident": serialize_incident(incident, assignment)}


@app.get("/api/incidents/{incident_id}/notes")
def incident_notes(incident_id: int, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    items = session.scalars(select(AnalystNote).where(AnalystNote.incident_id == incident.incident_id).order_by(AnalystNote.created_at.desc())).all()
    return {"items": [serialize_note(item) for item in items]}


@app.post("/api/incidents/{incident_id}/notes")
def add_incident_note(incident_id: int, payload: NoteInput, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = AnalystNote(incident_id=incident.incident_id, author=payload.author.strip(), content=payload.content.strip())
    session.add(note)
    log(session, "Analyst note added", incident.incident_id, actor=note.author)
    session.commit()
    return {"note": serialize_note(note)}


@app.get("/api/incidents/{incident_id}/evidence")
def incident_evidence(incident_id: int, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    items = session.scalars(select(EvidenceItem).where(EvidenceItem.incident_id == incident.incident_id).order_by(EvidenceItem.created_at.desc())).all()
    return {"items": [serialize_evidence(item) for item in items]}


@app.post("/api/incidents/{incident_id}/evidence")
def add_incident_evidence(incident_id: int, payload: EvidenceInput, request: Request, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    evidence = EvidenceItem(incident_id=incident.incident_id, title=payload.title.strip(), reference=payload.reference.strip(), sha256=payload.sha256.lower(), source=payload.source.strip(), note=payload.note.strip())
    session.add(evidence)
    actor = getattr(getattr(request.state, "user", None), "username", "analyst")
    log(session, "Evidence registered", incident.incident_id, actor=actor)
    session.commit()
    return {"evidence": serialize_evidence(evidence)}


@app.get("/api/incidents/{incident_id}/report")
def incident_report(incident_id: int, session: Session = Depends(get_session)):
    incident = session.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = session.scalars(select(Alert).where(Alert.campaign_id == incident.campaign_id).order_by(Alert.created_at.desc())).all()
    notes = session.scalars(select(AnalystNote).where(AnalystNote.incident_id == incident.incident_id).order_by(AnalystNote.created_at.desc())).all()
    evidence_items = session.scalars(select(EvidenceItem).where(EvidenceItem.incident_id == incident.incident_id).order_by(EvidenceItem.created_at.desc())).all()
    relationships = session.scalars(select(EntityRelationship).where(EntityRelationship.campaign_id == incident.campaign_id)).all()
    assignment = session.scalar(select(IncidentAssignment).where(IncidentAssignment.incident_id == incident.incident_id))
    return {
        "reportType": "FraudX Sentinel incident report",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "incident": serialize_incident(incident, assignment),
        "alerts": [serialize_alert(item) for item in alerts],
        "notes": [serialize_note(item) for item in notes],
        "evidenceRegister": [serialize_evidence(item) for item in evidence_items],
        "relationships": [{"source": item.source_id, "target": item.target_id, "relation": item.relation_type, "confidence": item.confidence, "evidence": item.evidence} for item in relationships],
        "disclaimer": "This report contains only locally ingested evidence. Findings require analyst validation before operational action.",
    }


@app.get("/api/campaigns")
def campaigns(session: Session = Depends(get_session)):
    return {"items": [serialize_campaign(item) for item in session.scalars(select(Campaign).order_by(Campaign.updated_at.desc())).all()]}


@app.get("/api/entities")
def entities(session: Session = Depends(get_session)):
    return {"items": [serialize_entity(item) for item in session.scalars(select(ThreatEntity).order_by(ThreatEntity.risk_score.desc())).all()]}


@app.get("/api/digital-dna/{entity_id}")
def digital_dna(entity_id: str, session: Session = Depends(get_session)):
    entity = session.scalar(select(ThreatEntity).where(ThreatEntity.entity_id == entity_id))
    if not entity:
        raise HTTPException(status_code=404, detail="Threat entity not found")
    indicators = {item.indicator_id: item for item in session.scalars(select(IntelligenceIndicator)).all()}
    incident_rows = {item.incident_id: item for item in session.scalars(select(Incident)).all()}
    relationships = session.scalars(select(EntityRelationship).where((EntityRelationship.source_id == entity_id) | (EntityRelationship.target_id == entity_id))).all()
    nodes = [{"id": entity.entity_id, "label": entity.label, "type": "ENTITY", "riskScore": entity.risk_score, "confidence": entity.confidence}]
    for relation in relationships:
        other_id = relation.target_id if relation.source_id == entity_id else relation.source_id
        if other_id in indicators:
            item = indicators[other_id]
            nodes.append({"id": item.indicator_id, "label": item.value, "type": item.indicator_type, "riskScore": item.risk_score, "confidence": item.confidence})
        elif other_id in incident_rows:
            item = incident_rows[other_id]
            nodes.append({"id": item.incident_id, "label": item.title, "type": "INCIDENT", "riskScore": 90, "confidence": 94})
    return {"entity": serialize_entity(entity), "nodes": nodes, "edges": [{"source": item.source_id, "target": item.target_id, "relation": item.relation_type, "confidence": item.confidence, "evidence": item.evidence} for item in relationships]}


@app.get("/api/digital-dna")
def latest_digital_dna(session: Session = Depends(get_session)):
    entity = session.scalar(select(ThreatEntity).order_by(ThreatEntity.last_seen.desc()))
    if not entity:
        return {"entity": None, "nodes": [], "edges": []}
    return digital_dna(entity.entity_id, session)


@app.get("/api/intelligence")
def intelligence(session: Session = Depends(get_session)):
    items = session.scalars(select(IntelligenceIndicator).order_by(IntelligenceIndicator.risk_score.desc())).all()
    return {"items": [{"indicatorId": item.indicator_id, "value": item.value, "type": item.indicator_type, "riskScore": item.risk_score, "confidence": item.confidence, "status": item.status, "source": item.source, "firstSeen": item.first_seen.isoformat(), "lastSeen": item.last_seen.isoformat()} for item in items]}


@app.get("/api/transactions")
def transactions(session: Session = Depends(get_session)):
    events = session.scalars(select(SecurityEvent).where(SecurityEvent.event_type == "TRANSACTION").order_by(SecurityEvent.timestamp.desc())).all()
    return {"items": [{**serialize_event(item), "metadata": json.loads(item.metadata_json or "{}") } for item in events]}


@app.get("/api/identity")
def identity(session: Session = Depends(get_session)):
    events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp.desc())).all()
    grouped = {}
    for item in events:
        record = grouped.setdefault(item.user_id, {"identity": item.user_id, "events": 0, "devices": set(), "ips": set(), "lastSeen": item.timestamp})
        record["events"] += 1
        record["devices"].add(item.device_id)
        record["ips"].add(item.source_ip)
        record["lastSeen"] = max(record["lastSeen"], item.timestamp)
    return {"items": [{"identity": item["identity"], "events": item["events"], "devices": len(item["devices"]), "ips": len(item["ips"]), "risk": min(100, 25 + item["events"] * 8 + max(0, len(item["devices"]) - 1) * 15), "lastSeen": item["lastSeen"].isoformat()} for item in grouped.values()]}


@app.get("/api/detection-rules")
def detection_rules(session: Session = Depends(get_session)):
    ensure_detection_rules(session)
    items = session.scalars(select(DetectionRule).order_by(DetectionRule.rule_id)).all()
    return {"items": [{"id": item.id, "ruleId": item.rule_id, "name": item.name, "category": item.category, "severity": item.severity, "status": "ENABLED" if item.enabled else "DISABLED", "enabled": item.enabled, "logic": item.logic, "updatedAt": item.updated_at.isoformat()} for item in items]}


@app.patch("/api/detection-rules/{rule_id}")
def update_detection_rule(rule_id: str, action: RuleAction, request: Request, session: Session = Depends(get_session)):
    require_admin(request)
    rule = session.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    rule.enabled = action.enabled
    log(session, f"Detection rule {'enabled' if action.enabled else 'disabled'}", rule.rule_id, actor="analyst")
    session.commit()
    return {"ruleId": rule.rule_id, "enabled": rule.enabled}


@app.get("/api/investigations/summary")
def investigation_summary(session: Session = Depends(get_session)):
    incident = session.scalar(select(Incident).order_by(Incident.updated_at.desc()))
    if not incident:
        return {"available": False, "summary": "Import or submit local events to create an evidence-backed investigation."}
    alerts = session.scalars(select(Alert).where(Alert.campaign_id == incident.campaign_id).order_by(Alert.risk_score.desc())).all()
    evidence = [item.evidence for item in alerts[:5]]
    return {"available": True, "incident": serialize_incident(incident), "summary": "This case summary is derived only from the locally ingested event and its matching detection rule. The disposition remains analyst-controlled; the platform does not attribute real-world threat actors.", "evidence": evidence, "recommendedActions": ["Confirm scope using the Digital DNA relationships.", "Validate the source event before containment.", "Document disposition and retain the audit record."]}
