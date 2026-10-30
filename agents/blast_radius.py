
"""
Blast Radius Analysis Agent
Simulation only. Never executes infrastructure changes.
"""

# Service -> services it depends on
SERVICE_DEPENDENCIES = {
    "authentication-service": [],

    "admin-portal": [
        "authentication-service"
    ],

    "finance-api": [
        "authentication-service"
    ],

    "user-dashboard": [
        "authentication-service"
    ],

    "notification-service": [
        "authentication-service"
    ]
}


def get_all_services():
    return list(SERVICE_DEPENDENCIES.keys())


def assess_blast_radius(target_service):

    target_service = target_service.strip().lower()

    if target_service not in SERVICE_DEPENDENCIES:
        raise ValueError("Unknown target service")

    # Find services that depend directly or indirectly
    # on the target service.

    affected = set()
    queue = [target_service]

    while queue:

        current = queue.pop(0)

        for service, dependencies in SERVICE_DEPENDENCIES.items():

            if (
                current in dependencies
                and service not in affected
            ):
                affected.add(service)
                queue.append(service)

    
# Identify direct dependents
    direct_dependents = sorted([
        service
        for service, dependencies in SERVICE_DEPENDENCIES.items()
        if target_service in dependencies
    ])

# Services affected directly or indirectly
    impacted = sorted(affected)

# Identify indirect dependents
    indirect_dependents = sorted(
        set(impacted) - set(direct_dependents)
    )

# Count affected services
    count = len(impacted)

    # Risk classification for demonstration.
    if count >= 4:
        risk = "Critical"
    elif count >= 2:
        risk = "High"
    elif count == 1:
        risk = "Low"
    else:
        risk = "None"

    return {
        "target_service": target_service,
        "affected_services": impacted,
        "direct_dependents": direct_dependents,
        "indirect_dependents": indirect_dependents,
        "direct_dependencies": SERVICE_DEPENDENCIES[target_service],
        "total_affected": count,
        "risk_level": risk,
        "simulation_only": True,
        "recommendation": (
            "Review all affected services before approval."
            if count > 1
            else "No downstream dependents detected."
            if count == 0
            else "One dependent service detected. Review before approval."
        )
    }
