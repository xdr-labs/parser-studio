"""Offline-only provisional syslog listener port comparison.

A candidate is absent from the observed custom and system catalogue ports,
NOT reserved or guaranteed to be available at the DP/sensor runtime.
"""
SYSLOG_MIN_PORT = 6800
SYSLOG_MAX_SUGGESTED_PORT = 30000


def propose_from_ports(custom_ports, catalog_ports, requested=None, *,
                       range_start=SYSLOG_MIN_PORT,
                       range_end=SYSLOG_MAX_SUGGESTED_PORT):
    if (type(range_start) is not int or type(range_end) is not int
            or range_start < SYSLOG_MIN_PORT or range_end > 65535
            or range_start > range_end):
        return {"status": "INVALID_RANGE", "candidate": None, "reserved": False}
    for rows in (custom_ports, catalog_ports):
        if (not isinstance(rows, list) or len(rows) > 10000 or
                any(type(p) is not int or p < 1 or p > 65535 for p in rows)):
            return {"status": "INCOMPLETE_EVIDENCE", "candidate": None, "reserved": False}
    occupied = set(custom_ports) | set(catalog_ports)
    count = len(occupied)
    if requested is None:
        port = next((p for p in range(range_start, range_end + 1)
                     if p not in occupied), None)
    else:
        if type(requested) is not int or not SYSLOG_MIN_PORT <= requested <= 65535:
            return {"status": "INVALID_OVERRIDE", "candidate": None, "reserved": False}
        port = requested
    if port is None:
        return {"status": "NO_CANDIDATE", "candidate": None, "reserved": False}
    return {
        "status": ("KNOWN_COLLISION" if port in occupied
                   else "CANDIDATE_REQUIRES_TARGET_RECHECK"),
        "candidate": port, "reserved": False,
        "observedDistinctPorts": count,
        "sensorBindingsVerified": False,
        "localReservationsVerified": False,
        "deploymentAuthorized": False,
    }
