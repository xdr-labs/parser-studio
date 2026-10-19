#!/usr/bin/env python3
"""Operator-invoked, strict read-only Stellar Cyber DP validation.

OFFLINE by default. --execute explicitly performs exactly:
  POST /connect/api/v1/access_token  (JWT exchange only)
  GET  /connect/api/v1/custom_log_parsers?cust_id=<profile tenant>
  GET  /connect/api/v1/custom_log_parsers/parsers?cust_id=<profile tenant>

No other route, unsafe host, mutation endpoint, redirect, sensor traffic,
customer logs, Key/JWT output, or persisted network response is permitted.
Secrets are loaded only when --execute is invoked at a trusted local TTY.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import ssl
import sys
from typing import Any, Callable
from urllib import error, parse, request
from port_inventory import SYSLOG_MIN_PORT, propose_from_ports

ALLOWED_POC_ORIGIN = "https://poc-apac.stellarcyber.cloud"
PREFIX = "/connect/api/v1"
AUTH_ROUTE = "/access_token"
GET_ROUTES = ("/custom_log_parsers", "/custom_log_parsers/parsers")
MAX_JSON_BYTES = 2_000_000
MAX_ROWS = 10_000
TIMEOUT_SECONDS = 18


class ReadonlyProbeError(Exception):
    """A fixed error code only, never vendor payloads or raw exception strings."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def no(code: str) -> None:
    raise ReadonlyProbeError(code)


def validate_origin(host: object) -> str:
    if host != ALLOWED_POC_ORIGIN:
        no("POC_ORIGIN_UNAUTHORIZED")
    return ALLOWED_POC_ORIGIN


def validated_profile(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != {"host", "tenant", "key"}:
        no("PROFILE_INVALID")
    validate_origin(value["host"])
    tenant, key = value["tenant"], value["key"]
    if (not isinstance(tenant, str) or not 1 <= len(tenant) <= 128
            or not all(c.isascii() and (c.isalnum() or c in "-_") for c in tenant)):
        no("TENANT_INVALID")
    if (not isinstance(key, str) or not 1 <= len(key) <= 8192
            or any(c in key for c in "\r\n\0")):
        no("KEY_INVALID")
    return value


def read_private_profile() -> dict:
    # No local credential access happens unless the caller requested --execute.
    path = Path(__file__).with_name("configure-target.py")
    spec = importlib.util.spec_from_file_location("parser_studio_target_config", path)
    if spec is None or spec.loader is None:
        no("CONFIG_LOADER_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        local = module.read_profile()
    except Exception:
        no("PROFILE_UNAVAILABLE")
    if local is None:
        no("PROFILE_UNAVAILABLE")
    try:
        return validated_profile({
            "host": local["dp"]["url"],
            "tenant": local["dp"]["tenant_id"],
            "key": local["dp"]["api_key"],
        })
    except (KeyError, TypeError):
        no("PROFILE_INVALID")


def request_json(
    method: str,
    route: str,
    token: str,
    *,
    tenant: str | None,
    opener: Any = None,
) -> tuple[int, Any]:
    allowed = (method == "POST" and route == AUTH_ROUTE and tenant is None) or (
        method == "GET" and route in GET_ROUTES and isinstance(tenant, str))
    if not allowed:
        no("METHOD_OR_ROUTE_UNAUTHORIZED")
    if not isinstance(token, str) or not token or len(token) > 8192:
        no("TOKEN_INVALID")
    if tenant is None:
        suffix = route
    else:
        if not all(c.isascii() and (c.isalnum() or c in "-_") for c in tenant):
            no("TENANT_INVALID")
        suffix = route + "?" + parse.urlencode({"cust_id": tenant})
    url = ALLOWED_POC_ORIGIN + PREFIX + suffix
    client = opener if opener is not None else request.build_opener(
        request.ProxyHandler({}),
        request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    req = request.Request(
        url,
        method=method,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    try:
        with client.open(req, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            raw = response.read(MAX_JSON_BYTES + 1)
    except error.HTTPError as exc:
        code = exc.code
        exc.close()
        return code, None
    except (error.URLError, TimeoutError, OSError, ValueError):
        no("HTTPS_NETWORK_FAILURE")
    if len(raw) > MAX_JSON_BYTES:
        no("RESPONSE_TOO_LARGE")
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeError):
        no("RESPONSE_NOT_JSON")
    return status, parsed


def verify(
    profile: dict,
    *,
    send: Callable[..., tuple[int, Any]] = request_json,
    include_port_plan: bool = False,
    check_port: int | None = None,
) -> dict:
    """Returns metadata ONLY. NEVER returns a key, JWT, parser or raw data."""
    p = validated_profile(profile)
    if check_port is not None and (
        type(check_port) is not int or not SYSLOG_MIN_PORT <= check_port <= 65535
    ):
        no("PORT_INVALID")
    port_rows = {}
    auth_status, reply = send("POST", AUTH_ROUTE, p["key"], tenant=None)
    result = {
        "auth": {
            "httpStatus": auth_status,
            "jwtExchanged": False,
        },
        "reads": [],
        "operations": {
            "authExchange": 1,
            "get": 0,
            "parserWrites": 0,
            "sensorSends": 0,
        },
        "apiRegistrationVerified": False,
        "runtimeParsingVerified": False,
    }
    if auth_status != 200 or not isinstance(reply, dict):
        return result
    jwt = reply.get("access_token")
    if not isinstance(jwt, str) or not jwt or len(jwt) > 8192:
        return result
    result["auth"]["jwtExchanged"] = True

    for route in GET_ROUTES:
        status, response = send("GET", route, jwt, tenant=p["tenant"])
        result["operations"]["get"] += 1
        data = response.get("data") if isinstance(response, dict) else None
        valid = (
            status == 200
            and isinstance(data, list)
            and len(data) <= MAX_ROWS
            and all(isinstance(row, dict) for row in data)
        )
        port_count = None
        if valid:
            ports: set[int] = set()
            for row in data:
                value = row.get("port")
                if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535:
                    ports.add(value)
            port_count = len(ports) if ports else None
        if include_port_plan:
            # /custom_log_parsers is requested with cust_id, and each
            # explicit row tenant must match. But /parsers is the shared
            # built-in/global catalogue: a system or other tenant cust_id
            # still denotes an occupied port and MUST be included.
            full_ports = valid and all(
                type(item.get("port")) is int and 1 <= item["port"] <= 65535
                for item in data
            )
            tenant_valid = (
                route != GET_ROUTES[0] or all(
                    item.get("cust_id", p["tenant"]) == p["tenant"]
                    for item in data
                )
            ) if valid else False
            if full_ports and tenant_valid:
                port_rows[route] = [item["port"] for item in data]
            else:
                port_rows[route] = None
        result["reads"].append({
            "route": PREFIX + route,
            "httpStatus": status,
            "shapeValid": valid,
            "recordCount": len(data) if valid else None,
            "distinctReportedPorts": port_count,
        })
    if include_port_plan:
        custom = port_rows.get(GET_ROUTES[0])
        catalogue = port_rows.get(GET_ROUTES[1])
        result["portEvidence"] = (
            propose_from_ports(custom, catalogue, requested=check_port)
            if custom is not None and catalogue is not None
            else {"status": "INCOMPLETE_EVIDENCE", "candidate": None,
                  "reserved": False}
        )
    return result


def print_port_evidence(port_data: dict) -> None:
    """Show a tentative port without returning a vendor record or raw data."""
    print("PORT_INVENTORY_STATUS:", port_data["status"])
    print("PARSER_LISTENER_PORT_CANDIDATE:",
          port_data["candidate"] if port_data["candidate"] is not None else "NONE")
    if "observedDistinctPorts" in port_data:
        print("OBSERVED_DISTINCT_PORT_UNION:", port_data["observedDistinctPorts"])
    print("PORT_RESERVED: NO")
    print("SENSOR_BINDINGS: NOT_VERIFIED")
    print("LOCAL_RESERVATIONS: NOT_VERIFIED")
    print("PORT_READY_FOR_DEPLOYMENT: NO")


def print_result(result: dict) -> bool:
    print("JWT_EXCHANGE:", "PASS" if result["auth"]["jwtExchanged"] else "FAIL",
          "HTTP", result["auth"]["httpStatus"])
    for item in result["reads"]:
        print("GET", item["route"], "HTTP", item["httpStatus"],
              "shape", "PASS" if item["shapeValid"] else "NOT_VERIFIED",
              "records", item["recordCount"] if item["recordCount"] is not None else "UNKNOWN",
              "distinctReportedPorts", item["distinctReportedPorts"]
              if item["distinctReportedPorts"] is not None else "UNKNOWN")
    pass_read = result["auth"]["jwtExchanged"] and len(result["reads"]) == 2 and all(
        x["httpStatus"] == 200 and x["shapeValid"] for x in result["reads"])
    print("POC_READ_ONLY_VALIDATION:", "PASS" if pass_read else "NOT_VERIFIED")
    print("PARSER_WRITES=0 SENSOR_SENDS=0")
    print("PORT_COLLISION=NOT_VERIFIED RUNTIME_PARSING=NOT_VERIFIED")
    if "portEvidence" in result:
        print_port_evidence(result["portEvidence"])
    return bool(pass_read)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="POC JWT + read-only parser inventory check")
    parser.add_argument("--execute", action="store_true",
                        help="Perform approved JWT exchange POST and two tenant-scoped GETs")
    port_flags = parser.add_mutually_exclusive_group()
    port_flags.add_argument("--suggest-port", action="store_true",
                            help="Propose a port absent from the two inventory GETs")
    port_flags.add_argument("--check-port", type=int, metavar="PORT",
                            help="Check a user-selected listener port against the two GETs")
    args = parser.parse_args(argv)
    if (args.suggest_port or args.check_port is not None) and not args.execute:
        print("PORT_PRECHECK_REQUIRES_EXECUTE", file=sys.stderr)
        return 2
    if not args.execute:
        print("OFFLINE_ONLY: no credential read or network request.")
        print("To perform approved live JWT/GET verification, use --execute on dev-atlas.")
        print("NETWORK_ALLOWLIST: 1 JWT exchange POST, 2 parser inventory GET, no mutations.")
        return 0
    try:
        result = verify(read_private_profile(),
                        include_port_plan=(args.suggest_port or args.check_port is not None),
                        check_port=args.check_port)
        return 0 if print_result(result) else 1
    except ReadonlyProbeError as exc:
        print("READ_ONLY_PROBE_FAILED:", str(exc), file=sys.stderr)
        print("NO_PARSER_MUTATIONS_OR_SENSOR_SENDS", file=sys.stderr)
        return 2
    except Exception as exc:
        # Never expose exception strings that may contain a private URL,
        # Authorization header or vendor response.
        print("READ_ONLY_PROBE_FAILED: UNEXPECTED_" + type(exc).__name__, file=sys.stderr)
        print("NO_PARSER_MUTATIONS_OR_SENSOR_SENDS", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
