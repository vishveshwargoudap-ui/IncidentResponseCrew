import app as app_module


def test_delete_incident_removes_workflow_and_blast_radius_records(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "incidents.db")
    app_module.enable_sqlite_wal()
    app_module.init_db()
    client = app_module.app.test_client()

    incident_id = client.get("/api/incidents").get_json()["incidents"][0]["id"]
    assessment = client.post(
        f"/api/incidents/{incident_id}/blast-radius",
        json={"target_service": "authentication-service"},
    )
    assert assessment.status_code == 200

    response = client.delete(f"/api/incidents/{incident_id}")
    assert response.status_code == 200
    assert response.get_json()["deleted"] is True
    assert client.get(f"/api/incidents/{incident_id}").status_code == 404

    with app_module.connect() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM activity WHERE incident_id = ?", (incident_id,)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM blast_radius_assessments WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()[0] == 0


def test_delete_unknown_incident_returns_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "DB", tmp_path / "incidents.db")
    app_module.enable_sqlite_wal()
    app_module.init_db()

    response = app_module.app.test_client().delete("/api/incidents/INC-missing")
    assert response.status_code == 404
    assert response.get_json()["error"] == "Incident not found"
