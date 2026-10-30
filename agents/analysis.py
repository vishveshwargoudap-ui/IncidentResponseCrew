"""Analysis agent uses transparent rules and marks limited evidence."""
def analyze(incident, findings):
    types=findings.get("observed_event_types",{}); failed=sum(v for k,v in types.items() if k.lower() in {"login_failed","failed_login","authentication_failure"})
    if failed>=3: kind,severity="Suspected brute-force attempt","Critical"
    elif failed: kind,severity="Authentication anomaly","High"
    elif not findings.get("event_count"): kind,severity="Unknown activity","Informational"
    else: kind,severity="Unusual activity","Medium"
    return {"agent":"Analysis","incident_type":kind,"severity":severity,"impact":"Potential unauthorized access; no successful compromise is established by these events.","reasoning":[f"{failed} failed authentication event(s) observed." if failed else "No failed authentication events identified in the supplied sample."],"confidence":"medium" if failed else "low","uncertainty":"Classification is a rule-based hypothesis over supplied events, not a confirmed attribution."}
