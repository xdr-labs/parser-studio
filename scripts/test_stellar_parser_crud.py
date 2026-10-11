#!/usr/bin/env python3
"""One-shot, owner-approved POC Custom Parser API CRUD probe.

This is NOT a production deployer. It confines mutations to a randomly named
test parser in the one approved POC DP/tenant, and always attempts cleanup.
Published 7.0 modular JSON schema is a candidate, not a proven contract for
the legacy /custom_log_parsers REST API. Failures are treated as evidence.
"""

import argparse
import json
import re
import secrets
import sys

import requests

from probe_stellar_test_api import load_private_profile
from verified_pair_fixture import make_host_parser_pair, InvalidSyntheticFixture, TEST_NAME_RE

API_PREFIX = "/connect/api/v1"
APPROVED_POC = "https://poc-apac.stellarcyber.cloud"
TEST_NAME_PATTERN = re.compile(r"ps_api_crud_test_[0-9a-f]{6,16}\Z")
TIMEOUT = (10, 25)


class UnsafeCrudError(RuntimeError):
    """No target mutation was allowed by a preflight guard."""


def assert_test_name(name: str) -> None:
    if not TEST_NAME_PATTERN.fullmatch(name):
        raise UnsafeCrudError("Refusing to touch a non-test parser.")


def validate_target(profile: dict) -> None:
    if profile.get("host") != APPROVED_POC or not profile.get("tenant") or not profile.get("key"):
        raise UnsafeCrudError("Only the specifically authorized POC host and a private tenant profile are permitted.")


def make_modular_parser(name: str, port: int, version: str) -> dict:
    assert_test_name(name)
    if not 7800 <= port <= 7999:
        raise UnsafeCrudError("Test port must be in 7800..7999.")
    if version not in ("1.0.0", "1.0.1"):
        raise UnsafeCrudError("Unexpected parser test version.")
    # Matches the five-step JSON example in the official Stellar Cyber 7.0s
    # Parser Studio download/upload documentation, with inert metadata.
    return {
        "parser_name": name,
        "version": version,
        "config_json": {
            "steps": [
                {
                    "module_id": "udp_tcp_v2",
                    "step_type": "routing",
                    "enabled": True,
                    "parameters": {"protocol": "udp_tcp", "port": port},
                },
                {
                    "module_id": "generic_parsing_v1",
                    "step_type": "parsing",
                    "enabled": True,
                    "parameters": {
                        "parsing": [{
                            "type": "multi_regexp",
                            "params": {"expressions": [r"^(?<message>.*)$"]},
                        }],
                        "store_raw_msg": False,
                    },
                },
                {
                    "module_id": "normalization_v2",
                    "step_type": "normalization",
                    "enabled": True,
                    "parameters": {
                        "vendor": "parser_studio_lab",
                        "product": "api_crud_fixture",
                        "custom_namespace": "ns_parser_studio_lab",
                        "category": "syslog",
                        "msg_origin": {
                            "source": "parser_studio_api_crud",
                            "category": "syslog",
                            "vendor": "parser_studio_lab",
                        },
                        "msg_class": "parser_studio_api_crud",
                        "ignore_values": [],
                        "top_fields": {},
                        "vendor_fields": {},
                    },
                },
                {
                    "module_id": "enrichment_v2",
                    "step_type": "enrichment",
                    "enabled": True,
                    "parameters": {"_enrichment_fn": "def _enrichment(record)\n  record\nend"},
                },
                {
                    "module_id": "stellar_router_v2",
                    "step_type": "output",
                    "enabled": True,
                    "parameters": {},
                },
            ],
        },
    }


def read_records(session, base: str, jwt: str, tenant: str):
    r = session.get(
        base + "/custom_log_parsers",
        params={"cust_id": tenant},
        headers={"Authorization": "Bearer " + jwt, "Accept": "application/json"},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code != 200:
        raise UnsafeCrudError("Parser list preflight failed; aborting mutation.")
    try:
        records = r.json().get("data")
    except (ValueError, AttributeError):
        records = None
    if not isinstance(records, list) or any(not isinstance(x, dict) for x in records):
        raise UnsafeCrudError("Unexpected parser-list schema; aborting mutation.")
    return records


def same_parser(x: dict, name: str, tenant: str) -> bool:
    return x.get("parser_name") == name and x.get("cust_id", tenant) == tenant


def safe_error_diagnostic(response, *, name: str, tenant: str, jwt: str) -> dict:
    """Extract error messages without exposing a key/JWT/tenant/raw parser data."""
    try:
        obj = response.json()
    except (ValueError, TypeError, AttributeError):
        return {"shape": "non_json"}
    if not isinstance(obj, dict):
        return {"shape": type(obj).__name__}
    keys = [k for k in obj if isinstance(k, str) and re.fullmatch(r"[a-zA-Z_]{1,24}", k)]
    hints = []
    def leaves(value, depth=0):
        if depth > 4:
            return
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for val in list(value.values())[:12]:
                yield from leaves(val, depth + 1)
        elif isinstance(value, list):
            for val in value[:12]:
                yield from leaves(val, depth + 1)

    for key in ("detail", "details", "message", "error", "errors"):
        for text in leaves(obj.get(key)):
            if not isinstance(text, str) or not text:
                continue
            for secret in (tenant, jwt, name):
                text = text.replace(secret, "[redacted]")
            # Never return a value that resembles a long token, URL, or tenant ID.
            text = re.sub(r"[A-Za-z0-9_\-]{26,}", "[redacted]", text)
            text = re.sub(r"https?://\S+", "[url]", text)
            text = re.sub(r"\S+@\S+", "[email]", text)
            text = "".join(c for c in text if c.isprintable())[:240]
            if text:
                hints.append(text)
    return {"shape": "object", "fields": sorted(keys)[:12], "hints": hints[:3]}


def call_mutation(session, method: str, url: str, *, jwt: str, tenant: str,
                  name: str, port: int, version: str = "1.0.0",
                  error_sink: dict | None = None) -> int:
    assert_test_name(name)
    headers = {"Authorization": "Bearer " + jwt, "Accept": "application/json"}
    if method == "DELETE":
        result = session.delete(
            url, params={"cust_id": tenant}, headers=headers,
            allow_redirects=False, timeout=TIMEOUT,
        )
    else:
        data = {"cust_id": tenant, "version": version}
        if method == "POST":
            data["parser_name"] = name
        payload = json.dumps(
            make_modular_parser(name, port, version),
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        # This REST endpoint rejects a modular-only JSON upload with
        # `missing parser/conf files, or wrong parser/conf file name` (HTTP 422).
        # Supply the documented legacy JSON+CONF pair. The vendor returned
        # HTTP 400 'Invalid port config' when CONF contained comments only.
        # This local-only syslog listener uses an unassigned port, with an
        # explicit sink discarding test traffic. Never enable a live listener
        # on the user's other sensors or point real log sources at it.
        noop_conf = (
            "#2026/10/12\n"
            f"# Isolated API CRUD verification for {name}; no production sources\n"
            f"# cust_id={tenant}\n"
            "<source>\n"
            "  @type syslog\n"
            "  bind 127.0.0.1\n"
            f"  port {port}\n"
            "  tag parser_studio_api_crud\n"
            "</source>\n"
            "<match parser_studio_api_crud.**>\n"
            "  @type null\n"
            "</match>\n"
        ).encode("utf-8")
        files = [
            # Existing POC entries returned parser_file exactly equal to the
            # parser name (no suffix), and conf_file equal to name + '.conf'.
            ("file", (name, payload, "application/json")),
            ("file", (name + ".conf", noop_conf, "text/plain")),
        ]
        if method == "POST":
            result = session.post(
                url, data=data, files=files, headers=headers,
                allow_redirects=False, timeout=TIMEOUT,
            )
        elif method == "PUT":
            result = session.put(
                url, data=data, files=files, headers=headers,
                allow_redirects=False, timeout=TIMEOUT,
            )
        else:
            raise UnsafeCrudError("Unsupported mutation method.")
    if error_sink is not None and result.status_code != 200:
        error_sink.update(safe_error_diagnostic(result, name=name, tenant=tenant, jwt=jwt))
    return result.status_code


def run_crud(profile: dict, *, session=None, test_name=None, port=7891) -> dict:
    """Execute POST→GET→PUT→DELETE against a newly generated test-only identity."""
    validate_target(profile)
    name = test_name or "customized_ps_api_crud_test_" + secrets.token_hex(5)
    assert_test_name(name)
    make_modular_parser(name, port, "1.0.0")
    client = session if session is not None else requests.Session()
    base = profile["host"] + API_PREFIX
    summary = {
        "test_parser_name": name,
        "test_port": port,
        "auth_http": None,
        "baseline_count": None,
        "create_http": None,
        "create_error_diagnostic": {},
        "create_confirmed": False,
        "update_http": None,
        "update_confirmed": False,
        "delete_http": None,
        "cleanup_confirmed": False,
        "final_count": None,
        "residual_test_parsers": None,
        "transport_error": None,
    }
    post_sent = False
    try:
        r = client.post(
            base + "/access_token",
            headers={"Authorization": "Bearer " + profile["key"], "Accept": "application/json"},
            allow_redirects=False, timeout=TIMEOUT,
        )
        summary["auth_http"] = r.status_code
        if r.status_code != 200:
            return summary
        try:
            jwt = r.json().get("access_token")
        except (ValueError, AttributeError):
            jwt = None
        if not isinstance(jwt, str) or not jwt:
            return summary

        original = read_records(client, base, jwt, profile["tenant"])
        summary["baseline_count"] = len(original)
        if any(same_parser(x, name, profile["tenant"]) for x in original):
            raise UnsafeCrudError("Unique test parser already exists; no writes allowed.")

        # Avoid colliding with any current built-in/custom parser port even though
        # documented modular uploads start disabled. If the catalogue is missing
        # or unreadable, abort rather than guessing whether a listener is free.
        catalog = client.get(
            base + "/custom_log_parsers/parsers",
            params={"cust_id": profile["tenant"]},
            headers={"Authorization": "Bearer " + jwt, "Accept": "application/json"},
            allow_redirects=False, timeout=TIMEOUT,
        )
        if catalog.status_code != 200:
            raise UnsafeCrudError("Parser catalogue unavailable; no write attempted.")
        try:
            items = catalog.json().get("data")
        except (ValueError, AttributeError):
            items = None
        if not isinstance(items, list) or any(not isinstance(x, dict) for x in items):
            raise UnsafeCrudError("Parser catalogue schema unknown; no write attempted.")
        used_ports = set()
        for row in items:
            raw = row.get("port")
            if isinstance(raw, (int, float)) and not isinstance(raw, bool):
                used_ports.add(int(raw))
        if port in used_ports:
            raise UnsafeCrudError("Selected test port conflicts with an existing parser.")

        url = base + "/custom_log_parsers"
        owned_url = url + "/" + name
        try:
            post_sent = True
            summary["create_http"] = call_mutation(
                client, "POST", url, jwt=jwt, tenant=profile["tenant"],
                name=name, port=port,
                error_sink=summary["create_error_diagnostic"],
            )
            # The server's response may differ between releases. Use list membership
            # to prove identity, not an untrusted success-body interpretation.
            after_create = read_records(client, base, jwt, profile["tenant"])
            summary["create_confirmed"] = any(
                same_parser(x, name, profile["tenant"]) for x in after_create
            )
            if summary["create_http"] == 200 and summary["create_confirmed"]:
                summary["update_http"] = call_mutation(
                    client, "PUT", owned_url, jwt=jwt, tenant=profile["tenant"],
                    name=name, port=port, version="1.0.1",
                )
                if summary["update_http"] == 200:
                    # An HTTP 200 only proves request acceptance. Confirm the
                    # new persisted version from the actual read API.
                    updated = read_records(client, base, jwt, profile["tenant"])
                    summary["update_confirmed"] = any(
                        same_parser(x, name, profile["tenant"]) and x.get("version") == "1.0.1"
                        for x in updated
                    )
        finally:
            # Even if POST times out, the remote request may have committed.
            # Never touch a name that was present in the original baseline.
            if post_sent:
                exists = False
                try:
                    current = read_records(client, base, jwt, profile["tenant"])
                    exists = any(same_parser(x, name, profile["tenant"]) for x in current)
                except (requests.RequestException, UnsafeCrudError, ValueError) as exc:
                    summary["transport_error"] = "cleanup_precheck_" + type(exc).__name__
                # A 200 CREATE is sufficient ownership evidence even if a GET
                # temporarily fails: attempt cleanup without waiting for GET.
                if exists or summary["create_http"] == 200:
                    try:
                        summary["delete_http"] = call_mutation(
                            client, "DELETE", owned_url, jwt=jwt,
                            tenant=profile["tenant"], name=name, port=port,
                        )
                    except (requests.RequestException, UnsafeCrudError, ValueError) as exc:
                        summary["transport_error"] = "cleanup_delete_" + type(exc).__name__
                try:
                    final = read_records(client, base, jwt, profile["tenant"])
                    residue = sum(same_parser(x, name, profile["tenant"]) for x in final)
                    summary["residual_test_parsers"] = residue
                    summary["final_count"] = len(final)
                    summary["cleanup_confirmed"] = residue == 0
                except (requests.RequestException, UnsafeCrudError, ValueError) as exc:
                    summary["transport_error"] = "cleanup_verify_" + type(exc).__name__
    except (requests.RequestException, UnsafeCrudError, ValueError) as exc:
        # Credential-bearing URLs, request headers and response bodies must not
        # appear in logs or GitHub. Errors are shown by type only.
        summary["transport_error"] = summary["transport_error"] or type(exc).__name__
        if isinstance(exc, UnsafeCrudError):
            raise
    finally:
        if session is None:
            client.close()
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Owner-authorized disposable parser CRUD check in POC")
    parser.add_argument("--execute", action="store_true", help="Actually create/update/delete one unique disposable test parser")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: no credentials loaded and no API calls made. --execute requires explicit owner approval.")
        return 0

    try:
        result = run_crud(load_private_profile())
    except UnsafeCrudError as exc:
        print("SAFE_ABORT:", str(exc), file=sys.stderr)
        return 2

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if result["create_http"] == 200 and result["create_confirmed"] and result["update_http"] == 200 and result["update_confirmed"] and result["cleanup_confirmed"]:
        print("CRUD_RESULT: PASS")
        return 0
    if result["cleanup_confirmed"]:
        print("CRUD_RESULT: PARTIAL (no test parser residue; see HTTP codes)")
        return 1
    if result["create_http"] is None:
        print("CRUD_RESULT: NO_WRITE (auth/list preflight did not complete)")
        return 2
    print("CRUD_RESULT: UNVERIFIED_CLEANUP — investigate this exact test name before any further write")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
