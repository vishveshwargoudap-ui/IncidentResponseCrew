"""Verification agent compares follow-up synthetic events with the incident source."""
def verify(incident, followup_events):
    if not followup_events:
        return {"agent":"Verification","result":"Inconclusive","event_count":0,"explanation":"No follow-up events were supplied; containment cannot be verified."}
    source=incident.get("source")
    relevant=[e for e in followup_events if e.get("source")==source]
    suspicious=[e for e in relevant if str(e.get("type","")).lower() in {"login_failed","failed_login","authentication_failure"}]
    if suspicious: result, explanation="Not verified",f"{len(suspicious)} matching failed authentication event(s) remain in follow-up data."
    elif relevant: result, explanation="Not verified","Follow-up activity from the incident source remains; the supplied events do not show clear containment."
    else: result, explanation="Verified","No matching source activity appears in the supplied follow-up sample. This result is limited to those events."
    return {"agent":"Verification","result":result,"event_count":len(followup_events),"matching_source_events":len(relevant),"explanation":explanation,"evidence_limit":"Verification covers only user-supplied simulated follow-up events."}
