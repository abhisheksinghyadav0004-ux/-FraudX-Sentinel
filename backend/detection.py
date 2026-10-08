import json
from collections import Counter


def detect_event(event, recent_events, enabled_rule_ids=None):
    if enabled_rule_ids is None:
        enabled_rule_ids = {"RULE-BOOK-001", "RULE-PAY-001", "RULE-AUTH-001", "RULE-PHISH-001", "RULE-MFA-001"}
    metadata = json.loads(event.metadata_json or "{}")
    same_device = [item for item in recent_events if item.device_id == event.device_id]
    same_ip = [item for item in recent_events if item.source_ip == event.source_ip]
    failed_logins = [item for item in same_ip if item.event_type == "LOGIN" and "failed" in item.risk_context]

    if "RULE-BOOK-001" in enabled_rule_ids and event.event_type == "BOOKING_REQUEST" and len(same_device) >= 6:
        return ("CRITICAL", 88, "Ticket Booking Bot Abuse", "High booking velocity", f"{len(same_device)} requests from shared device {event.device_id}")
    if "RULE-PAY-001" in enabled_rule_ids and event.event_type == "TRANSACTION" and metadata.get("amount", 0) >= 50000 and metadata.get("new_beneficiary"):
        return ("HIGH", 76, "Payment Fraud", "New beneficiary high-value transfer", "New beneficiary combined with high transaction amount")
    if "RULE-AUTH-001" in enabled_rule_ids and event.event_type == "LOGIN" and len(failed_logins) >= 4:
        return ("HIGH", 71, "Credential Stuffing", "Repeated failed logins", f"{len(failed_logins)} failed login events from {event.source_ip}")
    if "RULE-PHISH-001" in enabled_rule_ids and event.event_type == "URL_CLICK" and "brand-impersonation" in event.risk_context:
        return ("HIGH", 74, "Phishing", "Brand impersonation URL", "Event context contains a brand impersonation signal")
    if "RULE-MFA-001" in enabled_rule_ids and event.event_type == "MFA" and "failed" in event.risk_context:
        return ("MEDIUM", 54, "Account Takeover", "MFA failure anomaly", "MFA challenge failed after suspicious login activity")
    return None


def alert_summary(alerts):
    severity = Counter(alert.severity for alert in alerts)
    category = Counter(alert.category for alert in alerts)
    return dict(severity), dict(category)
