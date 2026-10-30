
"""Incident fix proposal agent.

Generates recommendations only.
Does not execute infrastructure changes.
"""

def propose_fixes(incident, analysis, triage_result):

    incident_type = analysis.get(
        "incident_type", ""
    ).lower()

    proposals = []

    if "brute" in incident_type or "authentication" in incident_type:

        proposals = [
            {
                "title": "Rate-limit suspicious login attempts",
                "description": "Apply rate limiting to repeated failed login requests.",
                "risk": "Legitimate users may experience temporary delays.",
                "approval_required": True
            },
            {
                "title": "Review authentication logs",
                "description": "Check for successful logins following repeated failures.",
                "risk": "Requires investigation of authentication records.",
                "approval_required": True
            }
        ]

    elif "network" in incident_type or "traffic" in incident_type:

        proposals = [
            {
                "title": "Investigate unusual network traffic",
                "description": "Inspect outbound traffic and identify unexpected connections.",
                "risk": "Investigation may require temporary monitoring overhead.",
                "approval_required": True
            },
            {
                "title": "Review network security rules",
                "description": "Check security groups and network access rules.",
                "risk": "Incorrect changes may interrupt legitimate traffic.",
                "approval_required": True
            }
        ]

    elif "cpu" in incident_type or "resource" in incident_type:

        proposals = [
            {
                "title": "Investigate resource utilization",
                "description": "Identify processes consuming excessive CPU or memory.",
                "risk": "Diagnostic collection may add minor system overhead.",
                "approval_required": True
            },
            {
                "title": "Evaluate infrastructure scaling",
                "description": "Assess whether additional compute capacity is required.",
                "risk": "Scaling may increase cloud costs.",
                "approval_required": True
            }
        ]

    else:

        proposals = [
            {
                "title": "Investigate affected infrastructure",
                "description": "Collect logs and inspect the affected asset.",
                "risk": "Investigation requires engineering time.",
                "approval_required": True
            }
        ]

    return {
        "agent": "Fix Proposal",
        "status": "completed",
        "priority": triage_result.get("priority", "P4"),
        "proposals": proposals,
        "simulated_only": True,
        "execution_enabled": False,
        "note": "Recommendations only. No infrastructure changes are executed."
    }

