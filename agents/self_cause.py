"""Correlate new incidents with recently approved, potentially disruptive actions."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any


DEFAULT_CORRELATION_WINDOW_SECONDS = 300

_INCIDENT_TIME_FIELDS = ("detected_at", "created_at", "occurred_at", "timestamp")
_SERVICE_FIELDS = ("service", "affected_service", "target_service", "asset", "component")
_ACTION_FIELDS = (
    "approved_action",
    "approved_actions",
    "response_action",
    "response_actions",
    "actions",
)
_ACTION_TEXT_FIELDS = ("action", "name", "description", "target", "resource")
_ASSESSMENT_FIELDS = (
    "blast_radius_assessment",
    "blast_radius",
    "blast_radius_result",
    "assessment",
    "assessment_json",
)


def detect_self_caused_incident(
    new_incident: Mapping[str, Any],
    prior_incidents: Sequence[Mapping[str, Any]],
    correlation_window_seconds: int | float = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> dict[str, Any]:
    """Find a possible link to a prior approved action without asserting causation.

    Prior incidents should include ``approved_at``, the concrete approved action
    (or response recommendations) in ``approved_action``/``actions``, and a
    blast-radius assessment. New incidents should include a detection or creation
    timestamp and a service/asset identifying the failing service.
    """
    if not isinstance(new_incident, Mapping):
        raise TypeError("new_incident must be a mapping")
    if (
        not isinstance(prior_incidents, Sequence)
        or isinstance(prior_incidents, (str, bytes))
    ):
        raise TypeError("prior_incidents must be a sequence of incident mappings")
    if any(not isinstance(incident, Mapping) for incident in prior_incidents):
        raise TypeError("every prior incident must be a mapping")
    if (
        isinstance(correlation_window_seconds, bool)
        or not isinstance(correlation_window_seconds, (int, float))
        or (
            isinstance(correlation_window_seconds, float)
            and not math.isfinite(correlation_window_seconds)
        )
        or correlation_window_seconds < 0
    ):
        raise ValueError("correlation_window_seconds must be a finite non-negative number")

    new_time = _incident_time(new_incident)
    new_services = _incident_services(new_incident)
    if new_time is None or not new_services:
        missing = []
        if new_time is None:
            missing.append("a valid detection/creation timestamp")
        if not new_services:
            missing.append("a recognizable affected service")
        return _inconclusive(
            new_incident,
            f"The new incident is missing {' and '.join(missing)}.",
            correlation_window_seconds,
        )

    exclusions: list[dict[str, str]] = []
    candidates: list[dict[str, Any]] = []

    for prior in prior_incidents:
        prior_id = _incident_id(prior)
        approved_time = _approval_time(prior)
        if approved_time is None:
            exclusions.append({
                "incident_id": prior_id,
                "reason": "No valid response approval timestamp was available.",
            })
            continue

        delay = (new_time - approved_time).total_seconds()
        if delay < 0:
            exclusions.append({
                "incident_id": prior_id,
                "reason": "The response was approved after the new incident was detected.",
            })
            continue
        if delay > correlation_window_seconds:
            exclusions.append({
                "incident_id": prior_id,
                "reason": "The approval fell outside the correlation time window.",
            })
            continue

        assessment = _blast_radius_assessment(prior)
        if assessment is None:
            exclusions.append({
                "incident_id": prior_id,
                "reason": "No blast-radius assessment was available.",
            })
            continue

        root_service = _normalize_service(assessment.get("target_service"))
        raw_affected_services = assessment.get("affected_services", [])
        if not isinstance(raw_affected_services, Sequence) or isinstance(
            raw_affected_services, (str, bytes)
        ):
            raw_affected_services = []
        affected_services = {
            normalized
            for service in raw_affected_services
            if (normalized := _normalize_service(service))
        }
        impacted_services = new_services & (affected_services | {root_service})
        if not impacted_services:
            exclusions.append({
                "incident_id": prior_id,
                "reason": "The new incident service was not in the assessed blast radius.",
            })
            continue

        known_services = affected_services | new_services
        if root_service:
            known_services.add(root_service)
        matching_action = _matching_action(prior, known_services, impacted_services, root_service)
        if matching_action is None:
            exclusions.append({
                "incident_id": prior_id,
                "reason": "No response action targeting the impacted service or its dependency was found.",
            })
            continue

        matched_service = sorted(impacted_services)[0]
        candidates.append({
            "incident_id": prior_id,
            "approved_at": approved_time.isoformat(),
            "failure_detected_at": new_time.isoformat(),
            "delay_seconds": round(delay, 3),
            "affected_service": matched_service,
            "action": matching_action["description"],
            "action_target_service": matching_action["target_service"],
            "root_service": root_service or None,
            "affected_services": sorted(affected_services),
            "assessment": assessment,
        })

    if not candidates:
        return {
            "agent": "Self-Cause Detector",
            "status": "no_correlation_found",
            "possible_self_cause": False,
            "new_incident_id": _incident_id(new_incident),
            "correlation_window_seconds": correlation_window_seconds,
            "excluded_prior_incidents": exclusions,
            "explanation": (
                "No approved response matched the new incident by time, affected "
                "service, and service-targeted action. This does not establish "
                "that the incidents are unrelated."
            ),
            "requires_human_review": False,
            "reconstruction_required": False,
        }

    match = min(candidates, key=lambda candidate: candidate["delay_seconds"])
    return {
        "agent": "Self-Cause Detector",
        "status": "possible_causal_link",
        "possible_self_cause": True,
        "confidence": "medium",
        "relationship": {
            "type": "possible_cause",
            "original_incident_id": match["incident_id"],
            "new_incident_id": _incident_id(new_incident),
            "affected_service": match["affected_service"],
            "approved_action": match["action"],
            "action_target_service": match["action_target_service"],
            "dependency_root_service": match["root_service"],
            "approved_at": match["approved_at"],
            "failure_detected_at": match["failure_detected_at"],
            "delay_seconds": match["delay_seconds"],
        },
        "correlation": {
            "time_window_seconds": correlation_window_seconds,
            "time_matched": True,
            "affected_service_matched": True,
            "approved_action_matched": True,
            "blast_radius_services": match["affected_services"],
        },
        "explanation": (
            f'{match["affected_service"]} failed {match["delay_seconds"]:g} seconds '
            f'after approval of an action targeting {match["action_target_service"]}. '
            "The service appears in that incident's blast-radius assessment."
        ),
        "uncertainty": (
            "Temporal and dependency correlation is a hypothesis, not proof that "
            "the approved action caused the failure. Confirm with incident evidence."
        ),
        "requires_human_review": True,
        "reconstruction_required": True,
        "human_review": {
            "status": "pending",
            "recommended_steps": [
                "Review the original incident, approved action, and blast-radius assessment.",
                "Compare service health and event timelines before and after the approval.",
                "Have an analyst confirm or reject the possible causal relationship.",
            ],
        },
        "excluded_prior_incidents": exclusions,
    }


def _inconclusive(
    incident: Mapping[str, Any],
    explanation: str,
    correlation_window_seconds: int | float,
) -> dict[str, Any]:
    return {
        "agent": "Self-Cause Detector",
        "status": "inconclusive",
        "possible_self_cause": None,
        "new_incident_id": _incident_id(incident),
        "correlation_window_seconds": correlation_window_seconds,
        "explanation": explanation,
        "requires_human_review": True,
        "reconstruction_required": False,
    }


def _incident_id(incident: Mapping[str, Any]) -> str | None:
    value = incident.get("id")
    return str(value) if value is not None else None


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _incident_time(incident: Mapping[str, Any]) -> datetime | None:
    for field in _INCIDENT_TIME_FIELDS:
        parsed = _parse_timestamp(incident.get(field))
        if parsed is not None:
            return parsed
    for event in _mapping_sequence(incident.get("events")):
        if isinstance(event, Mapping):
            for field in ("detected_at", "occurred_at", "timestamp", "time"):
                parsed = _parse_timestamp(event.get(field))
                if parsed is not None:
                    return parsed
    return None


def _approval_time(incident: Mapping[str, Any]) -> datetime | None:
    parsed = _parse_timestamp(incident.get("approved_at"))
    if parsed is not None:
        return parsed

    for activity in _mapping_sequence(incident.get("activity")):
        if not isinstance(activity, Mapping):
            continue
        if str(activity.get("agent", "")).casefold() != "response":
            continue
        output = _as_mapping(activity.get("output"))
        parsed = _parse_timestamp(output.get("approved_at"))
        if parsed is not None:
            return parsed
    return None


def _incident_services(incident: Mapping[str, Any]) -> set[str]:
    services: set[str] = set()
    for field in _SERVICE_FIELDS:
        normalized = _normalize_service(incident.get(field))
        if normalized:
            services.add(normalized)
    for event in _mapping_sequence(incident.get("events")):
        if not isinstance(event, Mapping):
            continue
        for field in _SERVICE_FIELDS:
            normalized = _normalize_service(event.get(field))
            if normalized:
                services.add(normalized)
    return services


def _blast_radius_assessment(incident: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for field in _ASSESSMENT_FIELDS:
        assessment = _as_mapping(incident.get(field))
        if assessment and (
            assessment.get("target_service") is not None
            or isinstance(assessment.get("affected_services"), list)
        ):
            return assessment

    for activity in _mapping_sequence(incident.get("activity")):
        if not isinstance(activity, Mapping):
            continue
        if str(activity.get("agent", "")).casefold() not in {
            "blast radius",
            "blast-radius",
            "blastradius",
        }:
            continue
        assessment = _as_mapping(activity.get("output"))
        if assessment and (
            assessment.get("target_service") is not None
            or isinstance(assessment.get("affected_services"), list)
        ):
            return assessment
    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return decoded if isinstance(decoded, Mapping) else {}
    return {}


def _mapping_sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return value
    return ()


def _normalize_service(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[\s_]+", "-", value.strip().casefold())


def _action_candidates(incident: Mapping[str, Any]) -> list[Any]:
    candidates: list[Any] = []
    for field in _ACTION_FIELDS:
        value = incident.get(field)
        if value is not None:
            candidates.append(value)
    for activity in _mapping_sequence(incident.get("activity")):
        if not isinstance(activity, Mapping):
            continue
        if str(activity.get("agent", "")).casefold() != "response":
            continue
        output = _as_mapping(activity.get("output"))
        if output:
            candidates.append(output)
    return candidates


def _matching_action(
    incident: Mapping[str, Any],
    known_services: set[str],
    impacted_services: set[str],
    root_service: str,
) -> dict[str, str] | None:
    for candidate in _action_candidates(incident):
        for action in _flatten_actions(candidate):
            target_services = _action_targets(action, known_services)
            valid_targets = target_services & (impacted_services | {root_service})
            if valid_targets:
                target = sorted(valid_targets)[0]
                description = _action_description(action)
                return {"description": description, "target_service": target}
    return None


def _flatten_actions(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        flattened: list[Any] = []
        for item in value:
            flattened.extend(_flatten_actions(item))
        return flattened
    if isinstance(value, Mapping):
        nested = value.get("actions")
        if isinstance(nested, Sequence) and not isinstance(nested, (str, bytes)):
            return _flatten_actions(nested)
    return [value] if isinstance(value, (Mapping, str)) else []


def _action_targets(action: Any, known_services: set[str]) -> set[str]:
    if isinstance(action, str):
        text = action.casefold()
        return {
            service
            for service in known_services
            if re.search(rf"(?<![\w-]){re.escape(service)}(?![\w-])", text)
        }
    if not isinstance(action, Mapping):
        return set()

    targets: set[str] = set()
    for field in _SERVICE_FIELDS:
        normalized = _normalize_service(action.get(field))
        if normalized in known_services:
            targets.add(normalized)
    text = " ".join(
        str(action[field])
        for field in _ACTION_TEXT_FIELDS
        if isinstance(action.get(field), str)
    ).casefold()
    targets.update(
        service
        for service in known_services
        if re.search(rf"(?<![\w-]){re.escape(service)}(?![\w-])", text)
    )
    return targets


def _action_description(action: Any) -> str:
    if isinstance(action, str):
        return action
    for field in _ACTION_TEXT_FIELDS:
        value = action.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "Approved service-targeted response action"