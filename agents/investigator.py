"""Investigation agent correlates supplied event fields."""
def investigate(incident):
    events=incident.get("events",[]); sources=sorted({str(e.get("source")) for e in events if e.get("source")})
    accounts=sorted({str(e.get("account")) for e in events if e.get("account")})
    types={}
    for event in events:
        kind=str(event.get("type","unknown")); types[kind]=types.get(kind,0)+1
    return {"agent":"Investigation","status":"completed","event_count":len(events),"observed_event_types":types,"suspected_sources":sources or [incident.get("source","unknown")],"affected_accounts":accounts,"affected_asset":incident.get("asset","unknown"),"findings":[f"Observed {len(events)} supplied event(s)."],"evidence_limit":"No external reputation, identity, or network data was queried."}
