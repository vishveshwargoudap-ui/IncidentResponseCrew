"""Safe response agent: recommendations only; no execution capability."""
def recommend(incident, analysis):
    proposed=[{"action":"Temporarily rate-limit the suspicious source","target_service":"authentication-service","reason":"Reduce repeated authentication attempts while preserving access for legitimate users.","risk":"May delay legitimate requests sharing this source.","expected_result":"Fewer repeated attempts in subsequent sample events."},
              {"action":"Review authentication logs and rotate affected credentials if compromise is confirmed","target_service":"authentication-service","reason":"Check whether any attempts succeeded before taking account-level steps.","risk":"Credential rotation interrupts the account owner.","expected_result":"Reduce risk if credential exposure is confirmed."}]
    incident_type = str(analysis.get("incident_type", "")).casefold()
    if "brute" in incident_type:
        proposed.append({
            "action": "Temporarily restrict authentication-service",
            "target_service": "authentication-service",
            "reason": "Limit authentication access while a suspected brute-force attack is investigated.",
            "risk": "May interrupt authentication for dependent services.",
            "expected_result": "Reduce exposure to repeated authentication attempts during investigation.",
        })

    return {"agent":"Response","status":"waiting_approval","simulated_only":True,"requires_human_approval":True,"actions":proposed,"note":"Approval records a simulated action only. No IP, account, or production system is changed."}
