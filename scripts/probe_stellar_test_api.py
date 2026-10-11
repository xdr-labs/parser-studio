#!/usr/bin/env python3
"""Read-only Stellar Cyber Parser API smoke probe (User Scope API Key).

The key is loaded from the local private profile, exchanged for a short-lived
JWT, and never printed, persisted again, or passed through command-line args.
Only POST /access_token (authentication) and explicitly allowlisted GET APIs
are used. No parser or tenant is created, edited, enabled, or deleted.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from urllib import error, parse, request

from configure_stellar_test_api import config_path, normalize_dp_url

MAX_RESPONSE_BYTES = 2_000_000
API_PREFIX = "/connect/api/v1"
READ_ONLY_ROUTES = ("/custom_log_parsers", "/custom_log_parsers/parsers")
DEFAULT_TIMEOUT_SECONDS = 20


class UnsafeProfileError(Exception):
    """Credentials may not be safely loaded."""


class ProbeRequestError(Exception):
    """Network, transport, or response decoding failed."""


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Do not forward credentials/JWT across HTTP redirects."""
        return None


def load_private_profile(path: Path | None = None) -> dict[str, str]:
    path = path if path is not None else config_path()
    try:
        directory = path.parent.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.getuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise UnsafeProfileError("Unsafe credentials directory.")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise UnsafeProfileError("Unsafe credentials file.")
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                fd = -1
                obj = json.load(stream)
        finally:
            if fd >= 0:
                os.close(fd)
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise UnsafeProfileError("Cannot safely load local API profile.") from exc

    if not isinstance(obj, dict):
        raise UnsafeProfileError("Invalid API profile.")
    try:
        host = normalize_dp_url(obj["dp_url"])
        tenant = obj["cust_id"]
        key = obj["api_key"]
        if not isinstance(tenant, str) or not tenant.strip() or any(c.isspace() for c in tenant):
            raise ValueError("Invalid tenant.")
        if not isinstance(key, str) or not key.strip() or key != key.strip():
            raise ValueError("Invalid key.")
    except (KeyError, ValueError, TypeError) as exc:
        raise UnsafeProfileError("Incomplete or invalid API profile.") from exc

    return {"host": host, "tenant": tenant, "key": key}


def request_json(
    method: str,
    url: str,
    bearer: str,
    *,
    opener=None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[int, object | None]:
    """Perform a bounded TLS-verified HTTPS request without following redirects."""
    if method not in {"GET", "POST"} or not url.startswith("https://"):
        raise ValueError("Only approved HTTPS read calls and JWT exchange are allowed.")
    client = opener if opener is not None else request.build_opener(NoRedirect())
    req = request.Request(
        url,
        method=method,
        headers={"Authorization": "Bearer " + bearer, "Accept": "application/json"},
    )
    try:
        with client.open(req, timeout=timeout) as response:
            status = response.status
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except error.HTTPError as exc:
        # Never echo server error bodies: they can contain identifiers or secrets.
        exc.close()
        return exc.code, None
    except (error.URLError, TimeoutError, OSError) as exc:
        raise ProbeRequestError(type(exc).__name__) from None

    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProbeRequestError("OversizedResponse")
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except (ValueError, UnicodeError):
        return status, None


def probe(profile: dict[str, str], *, send=request_json) -> dict:
    """Return only non-sensitive HTTP status codes, counts, and response shapes."""
    base = profile["host"] + API_PREFIX
    status, payload = send("POST", base + "/access_token", profile["key"])
    result = {"auth": {"status": status, "jwt_exchanged": False}, "endpoints": []}

    if status != 200:
        return result

    jwt = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(jwt, str) or not jwt:
        return result
    result["auth"]["jwt_exchanged"] = True

    params = parse.urlencode({"cust_id": profile["tenant"]})
    for route in READ_ONLY_ROUTES:
        status, obj = send("GET", base + route + "?" + params, jwt)
        records = obj.get("data") if isinstance(obj, dict) else None
        result["endpoints"].append(
            {
                "method": "GET",
                "path": API_PREFIX + route,
                "status": status,
                "result_type": "data-list" if isinstance(records, list) else "other",
                "count": len(records) if isinstance(records, list) else None,
            }
        )
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Stellar Cyber API read-only health and parser-list probe")
    parser.add_argument("--json", action="store_true", help="Output redacted machine-readable summary")
    args = parser.parse_args(argv)
    try:
        output = probe(load_private_profile())
    except (UnsafeProfileError, ProbeRequestError, ValueError) as exc:
        # Never print HTTP headers, exception URLs, response bodies, or tokens.
        print("Probe failed: " + type(exc).__name__, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(output, ensure_ascii=False))
    else:
        auth = output["auth"]
        print("JWT exchange:", "PASS" if auth["jwt_exchanged"] else "FAIL", "HTTP", auth["status"])
        for item in output["endpoints"]:
            print(item["method"], item["path"], "HTTP", item["status"], "records", item["count"])
        print("Read-only probe: no parser state was changed.")
    return 0 if output["auth"]["jwt_exchanged"] and all(
        item["status"] == 200 and item["result_type"] == "data-list"
        for item in output["endpoints"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
