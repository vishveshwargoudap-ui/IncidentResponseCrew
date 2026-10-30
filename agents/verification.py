
"""Verification agent compares follow-up synthetic events with the original incident."""

SUSPICIOUS_EVENT_TYPES = {
    "login_failed",
    "failed_login",
    "authentication_failure",
    "login_failure",
    "brute_force"
}


def verify(incident, followup_events):

    # Step 1: Validate incident
    if not isinstance(incident, dict):
        return {
            "agent": "Verification",
            "result": "Inconclusive",
            "event_count": 0,
            "explanation": "Invalid incident data."
        }

    # Step 2: Validate follow-up events
    if not isinstance(followup_events, list):
        return {
            "agent": "Verification",
            "result": "Inconclusive",
            "event_count": 0,
            "explanation": "Follow-up events must be a JSON array."
        }

    if not followup_events:
        return {
            "agent": "Verification",
            "result": "Inconclusive",
            "event_count": 0,
            "matching_source_events": 0,
            "explanation": "No follow-up events were supplied. "
                           "Containment cannot be verified."
        }

    # Step 3: Get original incident details
    source = str(incident.get("source") or "").strip()
    account = str(incident.get("account") or "").strip()
    asset = str(incident.get("asset") or "").strip()

    if not source:
        return {
            "agent": "Verification",
            "result": "Inconclusive",
            "event_count": len(followup_events),
            "explanation": "Original incident source IP is missing."
        }

    # Step 4: Match follow-up events with original source
    relevant = []

    for event in followup_events:

        if not isinstance(event, dict):
            continue

        event_source = str(event.get("source") or "").strip()

        if event_source == source:
            relevant.append(event)

    # Step 5: Identify suspicious activity
    suspicious = []

    for event in relevant:

        event_type = str(event.get("type") or "").strip().lower()

        if event_type in SUSPICIOUS_EVENT_TYPES:
            suspicious.append(event)

    # Step 6: Determine verification result
    if suspicious:

        result = "Not verified"

        explanation = (
            f"{len(suspicious)} matching suspicious authentication "
            "event(s) remain in the follow-up sample. "
            "Containment cannot be confirmed."
        )

    elif relevant:

        result = "Not verified"

        explanation = (
            f"{len(relevant)} event(s) from the original incident "
            "source remain. Further investigation is required."
        )

    else:

        result = "Verified"

        explanation = (
            "No matching source activity appears in the supplied "
            "follow-up sample. This result is limited to those events."
        )

    # Step 7: Return structured result
    return {
        "agent": "Verification",
        "result": result,
        "event_count": len(followup_events),
        "matching_source_events": len(relevant),
        "suspicious_events": len(suspicious),
        "incident_source": source,
        "evidence_limit": (
            "Verification covers only user-supplied "
            "simulated follow-up events."
        ),
        "explanation": explanation
    }
