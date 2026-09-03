"""
SPEMCS V1 Risk Scoring Engine (Specification Section 14)
Calculates real-time risk scores (0-100) per device/session based on security violations.

Risk Categories:
  0–20   -> Normal (Compliant)
  21–40  -> Low Risk
  41–60  -> Medium Risk
  61–80  -> High Risk
  81–100 -> Critical
"""

from typing import List, Optional
from uuid import UUID
from sqlalchemy.orm import Session

from backend.models.event import Event
from backend.models.alert import Alert


def calculate_risk_score(events: List[Event]) -> dict:
    """Calculate cumulative risk score for a collection of events."""
    if not events:
        return {
            "score": 0,
            "level": "normal",
            "violations_count": 0,
            "breakdown": []
        }

    score = 0
    breakdown = []

    unauthorized_count = 0
    remote_access_count = 0

    for ev in events:
        event_type = (ev.event_type or "").upper()
        proc_name = (ev.process_name or "").lower()
        reason = (ev.reason or "").lower()

        event_points = 0
        rule_applied = "Standard Event"

        # 1. Remote Access / Control Tools (+40)
        if any(kw in proc_name or kw in reason for kw in [
            "dwagent", "dwagsvc", "dwrcs", "anydesk", "teamviewer", "rustdesk",
            "ultraviewer", "parsec", "splashtop", "ammyy", "supremo", "vnc", "screenconnect"
        ]):
            event_points = 40
            rule_applied = f"Remote Access Tool ({ev.process_name})"
            remote_access_count += 1

        # 2. AI Assistants & Communication (+30)
        elif any(kw in proc_name or kw in reason for kw in [
            "chatgpt", "claude", "codex", "copilot", "gemini", "discord", "telegram"
        ]):
            event_points = 30
            rule_applied = f"Unauthorized AI/Communication Tool ({ev.process_name})"
            unauthorized_count += 1

        # 3. Unauthorized Applications / Unapproved Browsers (+25)
        elif "BLOCKED" in event_type or "UNAUTHORIZED" in event_type or "APPLICATION_OPENED" in event_type:
            event_points = 25
            rule_applied = f"Unauthorized Process ({ev.process_name})"
            unauthorized_count += 1

        # 4. Focus change / window switch (+10)
        elif "FOCUS" in event_type:
            event_points = 10
            rule_applied = "Focus Lost / Window Switch"

        # 5. Device Disconnect / Agent Interruption (+50)
        elif "DISCONNECT" in event_type or "AGENT_STOPPED" in event_type:
            event_points = 50
            rule_applied = "Agent Disconnected / Heartbeat Lost"

        else:
            event_points = 15
            rule_applied = f"Security Event: {ev.event_type}"

        score += event_points
        breakdown.append({
            "event_id": str(ev.event_id),
            "points": event_points,
            "rule": rule_applied,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None
        })

    # Repeated violations penalty (+30)
    if len(events) >= 3:
        score += 30
        breakdown.append({"points": 30, "rule": "Repeated Policy Violations Penalty"})

    # Clamp score to 0-100
    final_score = min(100, max(0, score))

    if final_score <= 20:
        level = "normal"
    elif final_score <= 40:
        level = "low"
    elif final_score <= 60:
        level = "medium"
    elif final_score <= 80:
        level = "high"
    else:
        level = "critical"

    return {
        "score": final_score,
        "level": level,
        "violations_count": len(events),
        "breakdown": breakdown
    }


def get_device_risk_score(db: Session, device_id: UUID) -> dict:
    """Compute current risk score for a specific device based on recent events."""
    events = db.query(Event).filter(Event.device_id == device_id).all()
    return calculate_risk_score(events)


def get_session_risk_score(db: Session, session_id: UUID) -> dict:
    """Compute risk score for an active exam session."""
    events = db.query(Event).filter(Event.session_id == session_id).all()
    return calculate_risk_score(events)
