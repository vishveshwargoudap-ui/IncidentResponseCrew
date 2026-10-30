"""Flask API and UI for the simulated Incident Response Crew MVP."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from agents.analysis import analyze
from agents.detection import detect
from agents.investigator import investigate
from agents.reporting import build_report
from agents.response import recommend
from agents.verification import verify

BASE = Path(__file__).resolve().parent
DB = BASE / "data" / "incidents.db"
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def event(db, incident_id, agent, status, output):
    db.execute("INSERT INTO activity (incident_id, agent, status, output, created_at) VALUES (?, ?, ?, ?, ?)",
               (incident_id, agent, status, json.dumps(output), now()))


def init_db():
    DB.parent.mkdir(exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
          id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
          incident_type TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
          source TEXT NOT NULL, asset TEXT NOT NULL, created_at TEXT NOT NULL,
          evidence TEXT NOT NULL, findings TEXT NOT NULL, actions TEXT NOT NULL,
          verification TEXT, approved_at TEXT, timeline TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activity (
          id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
          agent TEXT NOT NULL, status TEXT NOT NULL, output TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        if db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0:
            samples = [
              {"id":"INC-1042", "title":"Brute Force Attack", "description":"Repeated failed authentication attempts against the administrator portal.", "source":"198.51.100.24", "asset":"admin-portal-01", "severity":"Critical", "events":[{"time":"09:14:02Z","type":"login_failed","account":"admin","source":"198.51.100.24"},{"time":"09:14:19Z","type":"login_failed","account":"admin","source":"198.51.100.24"},{"time":"09:14:37Z","type":"login_failed","account":"admin","source":"198.51.100.24"},{"time":"09:15:01Z","type":"login_failed","account":"admin","source":"198.51.100.24"}]},
              {"id":"INC-1041", "title":"Suspicious Login", "description":"New location sign-in followed by an unusual access pattern.", "source":"203.0.113.18", "asset":"finance-workspace", "severity":"High", "events":[{"time":"08:42:11Z","type":"login_success","account":"analyst-02","source":"203.0.113.18"},{"time":"08:43:09Z","type":"file_access","account":"analyst-02","source":"203.0.113.18"}]},
              {"id":"INC-1039", "title":"Unusual Network Traffic", "description":"Outbound traffic volume exceeded the normal sample baseline.", "source":"app-node-03", "asset":"egress-gateway", "severity":"Medium", "events":[{"time":"07:58:00Z","type":"egress_spike","bytes":82400000,"source":"app-node-03"}]}
            ]
            for item in samples:
                created = now()
                detection = detect(item)
                findings = investigate(item)
                analysis = analyze(item, findings)
                actions = recommend(item, analysis)
                timeline = [{"at":created,"label":"Sample incident ingested","detail":"Synthetic event data"}]
                db.execute("INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                  (item["id"], item["title"], item["description"], analysis["incident_type"], analysis["severity"], "Active", item["source"], item["asset"], created, json.dumps(item["events"]), json.dumps({"detection":detection,"investigation":findings,"analysis":analysis}), json.dumps(actions), json.dumps(timeline)))
                event(db,item["id"],"Detection","completed",detection)
                event(db,item["id"],"Investigation","completed",findings)
                event(db,item["id"],"Analysis","completed",analysis)
                event(db,item["id"],"Response","waiting_approval",actions)


def incident_dict(row):
    item = dict(row)
    for key in ("evidence", "findings", "actions", "verification", "timeline"):
        if item.get(key): item[key] = json.loads(item[key])
    item["is_sample"] = True
    return item


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/incidents")
def incidents():
    with connect() as db:
        rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
    result = [incident_dict(row) for row in rows]
    return jsonify({"mode":"SIMULATED SAMPLE DATA", "incidents":result})


@app.get("/api/incidents/<incident_id>")
def incident(incident_id):
    with connect() as db:
        row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row: return jsonify({"error":"Incident not found"}), 404
    return jsonify(incident_dict(row))


@app.post("/api/incidents")
def create_incident():
    body = request.get_json(silent=True) or {}
    events = body.get("events")
    if not isinstance(events, list) or not events or any(not isinstance(event, dict) for event in events):
        return jsonify({"error":"Provide at least one simulated event in an events array."}), 400
    # Event strings are data only; no instructions or actions from event text are executed.
    title = str(body.get("title", "Submitted Sample Alert"))[:120]
    source = str(body.get("source", "unknown"))[:120]
    asset = str(body.get("asset", "unspecified asset"))[:120]
    iid = "INC-" + datetime.now().strftime("%H%M%S%f")
    sample = {"id":iid,"title":title,"description":str(body.get("description", "User supplied simulated events."))[:500],"source":source,"asset":asset,"events":events[:100]}
    detection, findings = detect(sample), investigate(sample)
    analysis = analyze(sample, findings)
    actions = recommend(sample, analysis)
    created = now(); timeline = [{"at":created,"label":"Sample incident ingested","detail":"User supplied simulated event data"}]
    with connect() as db:
        db.execute("INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)", (iid,title,sample["description"],analysis["incident_type"],analysis["severity"],"Active",source,asset,created,json.dumps(events[:100]),json.dumps({"detection":detection,"investigation":findings,"analysis":analysis}),json.dumps(actions),json.dumps(timeline)))
        for name, output in (("Detection",detection),("Investigation",findings),("Analysis",analysis),("Response",actions)):
            event(db,iid,name,"waiting_approval" if name=="Response" else "completed",output)
    return jsonify({"id":iid}), 201


@app.post("/api/incidents/<incident_id>/approve")
def approve(incident_id):
    with connect() as db:
        row = db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not row: return jsonify({"error":"Incident not found"}),404
        item = incident_dict(row)
        if row["approved_at"]: return jsonify({"error":"Simulated response already approved"}),409
        at=now(); timeline=item["timeline"]+[ {"at":at,"label":"Human approved simulated response","detail":"No real system or account was changed."} ]
        db.execute("UPDATE incidents SET status='Monitoring', approved_at=?, timeline=? WHERE id=?",(at,json.dumps(timeline),incident_id))
        event(db,incident_id,"Response","completed",{"approved":True,"simulated":True,"actions":item["actions"]})
    return jsonify({"ok":True,"simulated":True})


@app.post("/api/incidents/<incident_id>/verify")
def verify_incident(incident_id):
    body=request.get_json(silent=True) or {}
    followup=body.get("events")
    if not isinstance(followup,list): return jsonify({"error":"Provide follow-up events as an array."}),400
    with connect() as db:
        row=db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not row: return jsonify({"error":"Incident not found"}),404
        if not row["approved_at"]: return jsonify({"error":"Approve the simulated response before verification."}),409
        item=incident_dict(row); result=verify(item,followup)
        at=now(); status="Resolved" if result["result"]=="Verified" else "Monitoring"
        timeline=item["timeline"]+[ {"at":at,"label":"Follow-up verification","detail":result["result"]+": "+result["explanation"]} ]
        db.execute("UPDATE incidents SET status=?, verification=?, timeline=? WHERE id=?",(status,json.dumps(result),json.dumps(timeline),incident_id))
        event(db,incident_id,"Verification","completed",result)
    return jsonify({"verification":result,"status":status})


@app.get("/api/incidents/<incident_id>/report")
def report(incident_id):
    with connect() as db:
        row=db.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        activities=db.execute("SELECT agent,status,output,created_at FROM activity WHERE incident_id=? ORDER BY id",(incident_id,)).fetchall()
    if not row:return jsonify({"error":"Incident not found"}),404
    item=incident_dict(row); item["activity"]=[{**dict(a),"output":json.loads(a["output"])} for a in activities]
    return jsonify(build_report(item))


@app.get("/api/health")
def health(): return jsonify({"status":"ok","mode":"simulated demo"})


init_db()
if __name__ == "__main__": app.run(debug=True)
