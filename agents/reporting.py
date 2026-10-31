"""Build an exportable incident report from persisted workflow outputs."""
def build_report(incident):
    activities = incident.get("activity", [])
    causal = next((item.get("output", {}) for item in reversed(activities)
                   if item.get("agent") == "Self-Cause Detector"), {})
    return {"title":f"Incident report — {incident['id']}","mode":"SIMULATED SAMPLE DATA","incident":{k:incident.get(k) for k in ("id","title","description","incident_type","severity","status","source","asset","created_at")},"evidence":incident.get("evidence",[]),"findings":incident.get("findings",{}),"recommended_actions":incident.get("actions",{}),"approved_at":incident.get("approved_at"),"causal_chain":causal.get("causal_chain"),"recovery_recommendation":causal.get("recovery_recommendation"),"verification":incident.get("verification"),"timeline":incident.get("timeline",[]),"agent_activity":activities,"outcome_note":"A resolved status is shown only when the verification agent found no matching activity in supplied follow-up sample events."}
