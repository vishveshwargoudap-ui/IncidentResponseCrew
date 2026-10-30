
"""Incident triage agent."""

def triage(incident, analysis, findings):
    severity = analysis.get("severity", "Low")

    priorities = {
        "Critical": "P1",
        "High": "P2",
        "Medium": "P3",
        "Low": "P4",
        "Informational": "P4"
    }

    priority = priorities.get(severity, "P4")

    urgency = {
        "P1": "Immediate",
        "P2": "High",
        "P3": "Normal",
        "P4": "Low"
    }

    event_count = findings.get("event_count", 0)

    return {
        "agent": "Triage",
        "status": "completed",
        "incident_id": incident.get("id", "UNKNOWN"),
        "severity": severity,
        "priority": priority,
        "urgency": urgency[priority],
        "event_count": event_count,
        "affected_asset": incident.get("asset", "Unknown"),
        "reason": (
            f"Incident classified as {severity} "
            f"based on the analysis of {event_count} events."
        ),
        "recommended_team": (
            "Security Operations"
            if priority in ["P1", "P2"]
            else "DevOps Operations"
        )
    }

