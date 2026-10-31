
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

    # Track affected services and dependency levels
    affected = set()
    visited = {target_service}
    queue = [(target_service, 0)]

    service_levels = {}
    graph_edges = []

    # Traverse direct and indirect dependents
    while queue:

        current, level = queue.pop(0)

        for service, dependencies in SERVICE_DEPENDENCIES.items():

            if current in dependencies:

                # Store dependency connection
                edge = {
                    "from": current,
                    "to": service
                }

                if edge not in graph_edges:
                    graph_edges.append(edge)

                if service not in visited:

                    visited.add(service)
                    affected.add(service)

                    service_levels[service] = level + 1

                    queue.append((service, level + 1))

    # Direct dependents
    direct_dependents = sorted([
        service
        for service, dependencies in SERVICE_DEPENDENCIES.items()
        if target_service in dependencies
    ])

    impacted = sorted(affected)

    count = len(impacted)

    # Risk classification
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
        "direct_dependencies": SERVICE_DEPENDENCIES[target_service],
        "service_levels": service_levels,
        "graph_edges": graph_edges,
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
