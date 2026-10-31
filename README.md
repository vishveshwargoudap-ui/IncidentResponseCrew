# Incident Response Crew

A local Flask prototype for a simulated security operations workflow. It demonstrates structured alert detection, investigation, severity analysis, response recommendations with human approval, follow-up verification, and JSON incident reports.

> **Simulation only:** Seed incidents and actions are synthetic. User submitted events are treated as untrusted data. Approval records a simulated approval only; the app has no code or integration that blocks IPs, disables accounts, or changes external systems. A result is marked resolved only when follow-up data has no activity matching the incident source. An empty or continuing sample is inconclusive or not verified.

## Run locally

Requires Python 3.10+.

```powershell
cd IncidentResponseCrew
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. SQLite data is initialized in `data/incidents.db` on first run. To reset demo data, stop the app, remove that generated database file, and restart. No API key or external service is required.

## Demo flow

1. Open **Brute Force Attack** from the incident table and review the supplied failed-login evidence.
2. Review the Detection, Investigation, and Analysis agent outputs, including their evidence limits.
3. Review the recommended response and click **Approve simulated response**. This records an analyst approval only.
4. Supply follow-up sample events. Use `[]` to get **Inconclusive**, provide a failed login from `198.51.100.24` to get **Not verified**, or supply non-matching events to record a limited **Verified** result.
5. Export or download the incident report and inspect its timeline, findings, approval, and verification.

## API

- `GET /api/health` — local service status.
- `GET /api/incidents` — sample incident list.
- `GET /api/incidents/<id>` — incident evidence and agent outputs.
- `POST /api/incidents` — add a simulated incident, JSON body with `title`, `source`, `asset`, and non-empty `events` array.
- `POST /api/incidents/<id>/approve` — record simulated human approval.
- `POST /api/incidents/<id>/verify` — evaluate `{"events": [...]}` follow-up events after approval.
- `GET /api/incidents/<id>/report` — report data as JSON.

`agents.self_cause.detect_self_caused_incident(new_incident, prior_incidents)` correlates each newly created incident with prior approvals using a five-minute window, affected service, blast-radius membership, and a service-targeted approved action. Results are logged in the new incident's activity and are available from `GET /api/incidents/<id>/self-cause`. A match is a possible causal link requiring human review and reconstruction; it does not prove that the action caused the failure. Service-specific recommendations should include an explicit `target_service`; source-only recommendations are not assigned a fabricated service target.

Agent response fields are structured Python dictionaries persisted as JSON. Detection and classification use transparent local rules rather than an LLM. No live log source, threat intelligence, or external containment integration is configured.

## Project structure

- `app.py` — Flask routes, SQLite initialization, and workflow persistence.
- `agents/` — detection, investigation, analysis, response, self-cause correlation, verification, and reporting modules.
- `data/` — generated local SQLite database; `incidents.json` is retained as a legacy empty scaffold.
- `templates/index.html`, `static/` — responsive single page SOC dashboard.
- `simulator/` — existing simulator scaffold.

## Limitations

- Demo data and user-submitted events are the only evidence; no external feeds or real-world telemetry are connected.
- Agents use deterministic local rules and do not call an LLM.
- Verification is limited to a simple source and event comparison on supplied follow-up events; it does not prove real containment.
- The sample app is intended for a local hackathon demonstration, not production use. Add authentication, authorization, CSRF protection, deployment hardening, and audit retention before any shared deployment.
