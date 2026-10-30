"""Flask API and UI for the simulated Incident Response Crew MVP."""
from __future__ import annotations

import json
from random import sample
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
from agents.triage import triage
from agents.fix_proposal import propose_fixes

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
                triage_result = triage(item, analysis, findings)
                fixes= propose_fixes(item, analysis, triage_result)
                actions = recommend(item, analysis)
                actions = recommend(item, analysis)
                timeline = [{"at":created,"label":"Sample incident ingested","detail":"Synthetic event data"}]
                db.execute("INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                  (item["id"], item["title"], item["description"], analysis["incident_type"], analysis["severity"], "Active", item["source"], item["asset"], created, json.dumps(item["events"]), json.dumps({"detection":detection,"investigation":findings,"analysis":analysis,"triage":triage_result,"fix_proposals":fixes}), json.dumps(actions), json.dumps(timeline)))
                event(db,item["id"],"Detection","completed",detection)
                event(db,item["id"],"Investigation","completed",findings)
                event(db,item["id"],"Analysis","completed",analysis)
                event(db,item["id"],"Response","waiting_approval",actions)
                event(db,item["id"],"Triage","completed",triage_result)
                event(db,item["id"],"FixProposal","completed",fixes)


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
    
    # Step 1: Detection Agent
    detection = detect(sample)

    # Step 2: Investigation Agent
    findings = investigate(sample)

    # Step 3: Analysis Agent
    analysis = analyze(sample, findings)

    # Step 4: Triage Agent
    triage_result = triage(sample, analysis, findings)

    # Step 5: Fix Proposal Agent
    fixes = propose_fixes(sample, analysis, triage_result)

    # Step 6: Response Agent
    actions = recommend(sample, analysis)

    created = now(); timeline = [{"at":created,"label":"Sample incident ingested","detail":"User supplied simulated event data"}]
    with connect() as db:
        db.execute("INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)", (iid,title,sample["description"],analysis["incident_type"],analysis["severity"],"Active",source,asset,created,json.dumps(events[:100]),json.dumps({"detection":detection,"investigation":findings,"triage":triage_result,"fix_proposals":fixes,"analysis":analysis}),json.dumps(actions),json.dumps(timeline)))
        for name, output in (("Detection",detection),("Investigation",findings),("Analysis",analysis),("Triage",triage_result),("FixProposal",fixes),("Response",actions)):
            event(db,iid,name,"waiting_approval" if name=="Response" else "completed",output)
    return jsonify({"id":iid}), 201


@app.post("/api/incidents/<incident_id>/approve")
def approve(incident_id):

    with connect() as db:

        # Get incident
        row = db.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if not row:
            return jsonify({
                "error": "Incident not found"
            }), 404

        # Check whether already approved
        if row["approved_at"]:
            return jsonify({
                "ok": True,
                "simulated": True,
                "status": "Completed",
                "message": "Response was already approved."
            })

        # Record approval time
        approval_time = now()

        # Update incident timeline
        timeline = json.loads(row["timeline"] or "[]")

        timeline.append({
            "at": approval_time,
            "label": "Human approved simulated response",
            "detail": "No real system or account was changed."
        })

        # Save approval in SQLite
        db.execute("""
            UPDATE incidents
            SET approved_at = ?,
                timeline = ?
            WHERE id = ?
        """, (
            approval_time,
            json.dumps(timeline),
            incident_id
        ))

        # Update Response Agent execution status
        response_result = {
            "status": "Completed",
            "result": "Simulated approval recorded",
            "approved_at": approval_time,
            "simulated_only": True
        }

        event(
            db,
            incident_id,
            "Response",
            "completed",
            response_result
        )

    return jsonify({
        "ok": True,
        "simulated": True,
        "status": "Completed",
        "message": "Simulated response approved successfully."
    })

@app.get("/api/incidents/<incident_id>/agent-statuses")
def get_agent_statuses(incident_id):

    with connect() as db:

        row = db.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if not row:
            return jsonify({
                "error": "Incident not found"
            }), 404

        # Default agent statuses
        statuses = {
            "Detection": "Idle",
            "Investigation": "Idle",
            "Analysis": "Idle",
            "Response": "Idle",
            "Verification": "Idle",
            "Reporting": "Ready"
        }

        # Fetch latest execution for each agent
        activities = db.execute("""
            SELECT agent, status
            FROM activity
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

        for activity in activities:

            agent = activity["agent"]

            if agent in statuses and statuses[agent] in ("Idle", "Ready"):
                statuses[agent] = activity["status"].title()

    return jsonify({
        "incident_id": incident_id,
        "agents": statuses
    })


@app.post("/api/incidents/<incident_id>/verify")
def verify_incident(incident_id):
    body = request.get_json(silent=True) or {}
    followup = body.get("events")

    # 1. Validate follow-up events
    if not isinstance(followup, list):
        return jsonify({
            "error": "Follow-up events must be a JSON array."
        }), 400

    if not all(isinstance(event, dict) for event in followup):
        return jsonify({
            "error": "Every follow-up event must be a JSON object."
        }), 400

    # 2. Fetch incident
    with connect() as db:
        row = db.execute(
            "SELECT * FROM incidents WHERE id=?",
            (incident_id,)
        ).fetchone()

        if not row:
            return jsonify({
                "error": "Incident not found."
            }), 404

        # 3. Check simulated approval
        if not row["approved_at"]:
            return jsonify({
                "error": "Approve the simulated response before verification."
            }), 409

        # 4. Run Verification Agent
        item = incident_dict(row)
        result = verify(item, followup)

        # 5. Determine incident status
        if result["result"] == "Verified":
            status = "Resolved"

        elif result["result"] == "Not verified":
            status = "Monitoring"

        else:
            status = "Active"

        # 6. Update incident timeline
        at = now()
        timeline = item.get("timeline") or []

        timeline.append({
            "at": at,
            "label": "Follow-up verification",
            "detail": (
                f'{result["result"]}: '
                f'{result["explanation"]}'
            )
        })

        # 7. Save results in database
        db.execute(
            """
            UPDATE incidents
            SET status=?, verification=?, timeline=?
            WHERE id=?
            """,
            (
                status,
                json.dumps(result),
                json.dumps(timeline),
                incident_id
            )
        )

    # 8. Return API response
    return jsonify({
        "ok": True,
        "incident_id": incident_id,
        "verification": result,
        "status": status
    })

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
