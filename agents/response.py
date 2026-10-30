"""Safe response agent: recommendations only; no execution capability."""
def recommend(incident, analysis):
    proposed=[{"action":"Temporarily rate-limit the suspicious source","reason":"Reduce repeated authentication attempts while preserving access for legitimate users.","risk":"May delay legitimate requests sharing this source.","expected_result":"Fewer repeated attempts in subsequent sample events."},
              {"action":"Review authentication logs and rotate affected credentials if compromise is confirmed","reason":"Check whether any attempts succeeded before taking account-level steps.","risk":"Credential rotation interrupts the account owner.","expected_result":"Reduce risk if credential exposure is confirmed."}]
    return {"agent":"Response","status":"waiting_approval","simulated_only":True,"requires_human_approval":True,"actions":proposed,"note":"Approval records a simulated action only. No IP, account, or production system is changed."}
