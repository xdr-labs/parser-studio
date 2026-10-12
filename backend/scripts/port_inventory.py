"""Offline-only provisional listener port proposal from validated numeric inventory."""

def propose_from_ports(custom_ports, catalog_ports, requested=None):
    for rows in (custom_ports, catalog_ports):
        if not isinstance(rows, list) or len(rows) > 10000 or any(type(p) is not int or p < 1 or p > 65535 for p in rows):
            return {"status": "INCOMPLETE_EVIDENCE", "candidate": None, "reserved": False}
    occupied = set(custom_ports) | set(catalog_ports)
    count = len(occupied)
    if requested is None:
        port = next((p for p in range(20000, 30001) if p not in occupied), None)
    else:
        if type(requested) is not int or not 1024 <= requested <= 65535:
            return {"status": "INVALID_OVERRIDE", "candidate": None, "reserved": False}
        port = requested
    if port is None:
        return {"status": "NO_CANDIDATE", "candidate": None, "reserved": False}
    return {"status": "KNOWN_COLLISION" if port in occupied else "CANDIDATE_REQUIRES_TARGET_RECHECK", "candidate": port, "reserved": False, "observedDistinctPorts": count, "sensorBindingsVerified": False, "localReservationsVerified": False, "deploymentAuthorized": False}
