import json

import app as app_module
from agents.self_cause import detect_self_caused_incident


def test_correlates_failure_to_recent_approved_action_in_blast_radius():
    original = {
        "id": "INC-100",
        "approved_at": "2026-10-31T10:00:00Z",
        "approved_action": {
            "action": "Restrict authentication-service",
            "target_service": "authentication-service",
        },
        "blast_radius_assessment": {
            "target_service": "authentication-service",
            "affected_services": [
                "admin-portal",
                "finance-api",
                "user-dashboard",
                "notification-service",
            ],
        },
    }
    new_incident = {
        "id": "INC-101",
        "created_at": "2026-10-31T10:00:30Z",
        "asset": "finance-api",
    }

    result = detect_self_caused_incident(new_incident, [original])

    assert result["status"] == "possible_causal_link"
    assert result["possible_self_cause"] is True
    assert result["relationship"]["original_incident_id"] == "INC-100"
    assert result["relationship"]["affected_service"] == "finance-api"
    assert result["relationship"]["delay_seconds"] == 30
    assert result["requires_human_review"] is True
    assert result["reconstruction_required"] is True


def test_does_not_match_an_approval_outside_the_correlation_window():
    original = {
        "id": "INC-100",
        "approved_at": "2026-10-31T10:00:00Z",
        "approved_action": "Restrict authentication-service",
        "blast_radius_assessment": {
            "target_service": "authentication-service",
            "affected_services": ["finance-api"],
        },
    }
    new_incident = {
        "created_at": "2026-10-31T10:05:01Z",
        "asset": "finance-api",
    }

    result = detect_self_caused_incident(new_incident, [original])

    assert result["status"] == "no_correlation_found"
    assert result["possible_self_cause"] is False
    assert "outside the correlation time window" in result["excluded_prior_incidents"][0]["reason"]


def test_does_not_match_without_a_service_targeted_action():
    original = {
        "id": "INC-100",
        "approved_at": "2026-10-31T10:00:00Z",
        "actions": {
            "actions": [{"action": "Review authentication logs"}],
        },
        "blast_radius_assessment": {
            "target_service": "authentication-service",
            "affected_services": ["finance-api"],
        },
    }
    new_incident = {
        "created_at": "2026-10-31T10:00:30Z",
        "asset": "finance-api",
    }

    result = detect_self_caused_incident(new_incident, [original])

    assert result["status"] == "no_correlation_found"
    assert "No response action targeting" in result["excluded_prior_incidents"][0]["reason"]


def test_reads_approval_and_blast_radius_from_incident_activity():
    original = {
        "id": "INC-100",
        "actions": {
            "actions": [{"action": "Restrict authentication-service"}],
        },
        "activity": [
            {
                "agent": "Response",
                "output": {"approved_at": "2026-10-31T10:00:00Z"},
            },
            {
                "agent": "Blast Radius",
                "output": {
                    "target_service": "authentication-service",
                    "affected_services": ["finance-api"],
                },
            },
        ],
    }
    new_incident = {
        "created_at": "2026-10-31T10:00:30Z",
        "events": [{"service": "finance-api"}],
    }

    result = detect_self_caused_incident(new_incident, [original])

    assert result["status"] == "possible_causal_link"
    assert result["relationship"]["affected_service"] == "finance-api"


def test_returns_inconclusive_when_new_incident_lacks_time_or_service():
    result = detect_self_caused_incident({"id": "INC-101"}, [])

    assert result["status"] == "inconclusive"
    assert result["possible_self_cause"] is None
    assert result["requires_human_review"] is True


def test_incident_creation_logs_possible_link_without_approving_response(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(app_module, "DB", tmp_path / "incidents.db")
    app_module.enable_sqlite_wal()
    app_module.init_db()

    client = app_module.app.test_client()
    original_response = client.post(
        "/api/incidents",
        json={
            "title": "Brute Force Attack",
            "asset": "admin-portal",
            "source": "198.51.100.24",
            "events": [
                {"type": "login_failed", "source": "198.51.100.24"}
                for _ in range(3)
            ],
        },
    )
    assert original_response.status_code == 201
    original_id = original_response.get_json()["id"]

    detail = client.get(f"/api/incidents/{original_id}").get_json()
    assert all(action["impact_assessment"]["status"] == "complete"
               for action in detail["actions"]["actions"])
    assert any(action["target_service"] == "authentication-service"
               for action in detail["actions"]["actions"])
    assert client.post(f"/api/incidents/{original_id}/approve").status_code == 200

    with app_module.connect() as db:
        approved_output = db.execute(
            """
            SELECT output
            FROM activity
            WHERE incident_id = ? AND agent = 'Response' AND status = 'completed'
            ORDER BY id DESC LIMIT 1
            """,
            (original_id,),
        ).fetchone()
    approved_record = json.loads(approved_output["output"])
    service_action = next(
        action
        for action in approved_record["approved_action"]
        if action.get("target_service") == "authentication-service"
    )
    assert service_action["impact_assessment"]["target_service"] == "authentication-service"

    new_response = client.post(
        "/api/incidents",
        json={
            "title": "Finance API Failure",
            "asset": "finance-api",
            "events": [{"type": "service_failure", "service": "finance-api"}],
        },
    )
    assert new_response.status_code == 201
    new_id = new_response.get_json()["id"]

    detection_response = client.get(f"/api/incidents/{new_id}/self-cause")
    assert detection_response.status_code == 200
    result = detection_response.get_json()["result"]
    assert result["status"] == "possible_causal_link"
    assert result["relationship"]["original_incident_id"] == original_id
    assert result["relationship"]["affected_service"] == "finance-api"
    assert result["requires_human_review"] is True

    with app_module.connect() as db:
        new_incident = db.execute(
            "SELECT approved_at FROM incidents WHERE id = ?",
            (new_id,),
        ).fetchone()
        detector_activity = db.execute(
            """
            SELECT status
            FROM activity
            WHERE incident_id = ? AND agent = 'Self-Cause Detector'
            ORDER BY id DESC LIMIT 1
            """,
            (new_id,),
        ).fetchone()
        pending_response = db.execute(
            """
            SELECT status
            FROM activity
            WHERE incident_id = ? AND agent = 'Response'
            ORDER BY id DESC LIMIT 1
            """,
            (new_id,),
        ).fetchone()

    assert new_incident["approved_at"] is None
    assert detector_activity["status"] == "review_required"
    assert pending_response["status"] == "waiting_approval"


def test_unknown_target_assessment_blocks_approval(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "incidents.db")
    app_module.enable_sqlite_wal()
    app_module.init_db()
    with app_module.connect() as db:
        row = db.execute("SELECT id, actions FROM incidents LIMIT 1").fetchone()
        actions = json.loads(row["actions"])
        actions["actions"][0]["impact_assessment"] = {
            "status": "incomplete", "risk_level": "Unknown"
        }
        db.execute("UPDATE incidents SET actions = ? WHERE id = ?",
                   (json.dumps(actions), row["id"]))
    response = app_module.app.test_client().post(f"/api/incidents/{row['id']}/approve")
    assert response.status_code == 409
    assert "impact assessment" in response.get_json()["error"].lower()


def test_possible_link_includes_recovery_recommendation_and_report(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "incidents.db")
    app_module.enable_sqlite_wal()
    app_module.init_db()
    client = app_module.app.test_client()
    original = client.post("/api/incidents", json={
        "title": "Brute Force Attack", "asset": "admin-portal",
        "events": [{"type": "login_failed"} for _ in range(3)]
    }).get_json()["id"]
    assert client.post(f"/api/incidents/{original}/approve").status_code == 200
    subsequent = client.post("/api/incidents", json={
        "title": "Finance API Failure", "asset": "finance-api",
        "events": [{"type": "service_failure", "service": "finance-api"}]
    }).get_json()["id"]
    result = client.get(f"/api/incidents/{subsequent}/self-cause").get_json()["result"]
    assert result["causal_chain"]["status"] == "possible causal relationship"
    assert result["recovery_recommendation"]["status"] == "pending_human_approval"
    assert client.get(f"/api/incidents/{subsequent}/report").get_json()["causal_chain"]
    recovery = client.post(f"/api/incidents/{subsequent}/recovery/approve")
    assert recovery.status_code == 200
    assert "no rollback was executed" in recovery.get_json()["message"]
