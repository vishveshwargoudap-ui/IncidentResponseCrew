"""Rule-based detection agent for synthetic demo events."""
def detect(incident):
    events = incident.get("events", [])
    failed = [e for e in events if str(e.get("type", "")).lower() in {"login_failed", "failed_login", "authentication_failure"}]
    evidence = [{"event":e,"basis":"Failed authentication event in supplied sample data"} for e in failed[:10]]
    if len(failed) >= 3:
        title, kind, confidence = "Repeated failed logins detected", "suspected_brute_force", "high"
    elif failed:
        title, kind, confidence = "Failed login observed", "authentication_anomaly", "medium"
    elif events:
        title, kind, confidence = "Activity requires review", "anomalous_activity", "low"
    else:
        title, kind, confidence = "Insufficient event evidence", "unknown", "low"
    return {"agent":"Detection","status":"completed","alert_title":title,"incident_type":kind,"confidence":confidence,"evidence":evidence,"uncertainty":"Detection is based only on supplied synthetic events."}
