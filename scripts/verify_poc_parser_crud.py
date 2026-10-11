#!/usr/bin/env python3
"""One-shot, owner-approved POC-only Stellar Cyber Custom Parser CRUD probe.

Do not use against production or reuse an existing parser name. This script
creates a disposable uniquely named synthetic legacy parser, validates its
presence, attempts an update, and deletes only that same disposable parser.
It never uploads real customer logs or vendor-supplied parser code.
"""

import argparse
import json
import secrets
import sys
import time

import requests

from probe_stellar_test_api import load_private_profile
from verified_pair_fixture import InvalidSyntheticFixture, TEST_NAME_RE, make_host_parser_pair

APPROVED_POC_HOST = "https://poc-apac.stellarcyber.cloud"
ROUTE = "/connect/api/v1"
PORT = 7891
TIMEOUT = (10, 25)


class SafeAbort(Exception):
    pass


def validate_target(profile):
    if profile.get("host") != APPROVED_POC_HOST or not profile.get("tenant") or not profile.get("key"):
        raise SafeAbort("Only the owner-approved POC profile is allowed")


def safe_category(resp):
    """Recognize known generic errors without ever echoing server response data."""
    try:
        obj = resp.json()
        body = json.dumps(obj, ensure_ascii=False).lower()[:1500]
    except (ValueError, TypeError, AttributeError):
        return "non_json"
    if "missing parser/conf" in body:
        return "missing_or_wrong_pair_names"
    if "invalid port" in body:
        return "invalid_port"
    if "validation failed" in body:
        return "validation_failed"
    if resp.status_code == 403:
        return "forbidden"
    if resp.status_code == 401:
        return "unauthorized"
    return "other"


def read_list(client, base, jwt, tenant, *, route="custom_log_parsers"):
    r = client.get(
        base + "/" + route,
        params={"cust_id": tenant},
        headers={"Authorization": "Bearer " + jwt, "Accept": "application/json"},
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    if r.status_code != 200:
        raise SafeAbort("Parser list HTTP " + str(r.status_code))
    try:
        data = r.json().get("data")
    except (ValueError, TypeError, AttributeError):
        data = None
    if not isinstance(data, list) or any(not isinstance(e, dict) for e in data):
        raise SafeAbort("Unrecognized parser listing")
    return data


def contains_exact(items, name, tenant):
    return any(x.get("parser_name") == name and x.get("cust_id", tenant) == tenant for x in items)


def mutate(client, verb, url, *, jwt, tenant, name, files=None, version=None):
    if not TEST_NAME_RE.fullmatch(name) or APPROVED_POC_HOST not in url or "/custom_log_parsers" not in url:
        raise SafeAbort("Refusing to mutate non-test identity or non-POC URL")
    headers = {"Authorization": "Bearer " + jwt, "Accept": "application/json"}
    options = {"headers": headers, "timeout": TIMEOUT, "allow_redirects": False}
    if verb == "POST":
        if not files or not version:
            raise SafeAbort("Missing attested synthetic pair")
        r = client.post(url, data={"cust_id": tenant, "parser_name": name, "version": version},
                        files=files, **options)
    elif verb == "PUT":
        if not files or not version or not url.endswith("/" + name):
            raise SafeAbort("Invalid update identity")
        r = client.put(url, data={"cust_id": tenant, "version": version},
                       files=files, **options)
    elif verb == "DELETE":
        if not url.endswith("/" + name):
            raise SafeAbort("Invalid deletion identity")
        r = client.delete(url, params={"cust_id": tenant}, **options)
    else:
        raise SafeAbort("Unsupported verb")
    return r.status_code, safe_category(r) if r.status_code != 200 else ""


def run_crud(profile, *, session=None, test_name=None, port=PORT):
    validate_target(profile)
    name = test_name or "customized_ps_api_crud_test_" + secrets.token_hex(5)
    if not TEST_NAME_RE.fullmatch(name):
        raise SafeAbort("Only disposable test names are accepted")
    # Generate both versions before any live request. Verify the exact synthetic
    # native fixture hash, naming and input constraints. Refuse unvetted code.
    original_pair = make_host_parser_pair(name, port, "1.0.0")
    updated_pair = make_host_parser_pair(name, port, "1.0.1")
    owns_client = session is None
    client = session or requests.Session()
    base = profile["host"] + ROUTE
    report = {
        "test_parser_name": name, "test_port": port, "auth_http": None,
        "baseline_count": None, "create_http": None,
        "create_error_category": None, "create_confirmed": False,
        "update_http": None, "update_error_category": None,
        "update_verified": False, "delete_http": None,
        "cleanup_confirmed": False, "residual_test_parsers": None,
        "final_count": None, "error_type": None,
    }
    jwt = None
    post_attempted = False
    baseline_confirmed_absent = False
    try:
        auth = client.post(
            base + "/access_token",
            headers={"Authorization": "Bearer " + profile["key"], "Accept": "application/json"},
            timeout=TIMEOUT, allow_redirects=False,
        )
        report["auth_http"] = auth.status_code
        if auth.status_code != 200:
            return report
        obj = auth.json()
        jwt = obj.get("access_token") if isinstance(obj, dict) else None
        if not isinstance(jwt, str) or not jwt:
            raise SafeAbort("Invalid JWT response")
        original = read_list(client, base, jwt, profile["tenant"])
        report["baseline_count"] = len(original)
        if contains_exact(original, name, profile["tenant"]):
            raise SafeAbort("Test identity exists at baseline — no mutations")
        baseline_confirmed_absent = True

        catalog = read_list(
            client, base, jwt, profile["tenant"], route="custom_log_parsers/parsers"
        )
        for entry in catalog:
            existing_port = entry.get("port")
            if isinstance(existing_port, (int, float)) and existing_port == port:
                raise SafeAbort("Test listener port already assigned — no mutations")

        post_attempted = True
        code, category = mutate(
            client, "POST", base + "/custom_log_parsers",
            jwt=jwt, tenant=profile["tenant"], name=name,
            files=original_pair, version="1.0.0",
        )
        report["create_http"] = code
        report["create_error_category"] = category or None

        created = read_list(client, base, jwt, profile["tenant"])
        if code == 200 and not contains_exact(created, name, profile["tenant"]):
            time.sleep(0.5)
            created = read_list(client, base, jwt, profile["tenant"])
        report["create_confirmed"] = contains_exact(created, name, profile["tenant"])
        if code == 200 and report["create_confirmed"]:
            code, category = mutate(
                client, "PUT", base + "/custom_log_parsers/" + name,
                jwt=jwt, tenant=profile["tenant"], name=name,
                files=updated_pair, version="1.0.1",
            )
            report["update_http"] = code
            report["update_error_category"] = category or None
            if code == 200:
                updated = read_list(client, base, jwt, profile["tenant"])
                entry = next((x for x in updated if x.get("parser_name") == name
                              and x.get("cust_id", profile["tenant"]) == profile["tenant"]), None)
                # Version can be rewritten by DP. Explicitly report evidence
                # rather than claiming update verified from status code alone.
                report["update_verified"] = bool(
                    entry is not None and str(entry.get("version")) == "1.0.1"
                )
    except (requests.RequestException, SafeAbort, InvalidSyntheticFixture,
            ValueError, TypeError, KeyError) as exc:
        report["error_type"] = type(exc).__name__
    finally:
        if jwt and baseline_confirmed_absent and post_attempted:
            try:
                current = read_list(client, base, jwt, profile["tenant"])
                if contains_exact(current, name, profile["tenant"]) or report["create_http"] == 200:
                    report["delete_http"], _ = mutate(
                        client, "DELETE", base + "/custom_log_parsers/" + name,
                        jwt=jwt, tenant=profile["tenant"], name=name
                    )
                    if report["delete_http"] in (429, 500, 502, 503, 504):
                        # Retry only when the same unique test parser still exists.
                        # Never retry deletion for unrelated or pre-existing names.
                        check = read_list(client, base, jwt, profile["tenant"])
                        if contains_exact(check, name, profile["tenant"]):
                            time.sleep(0.2)
                            report["delete_http"], _ = mutate(
                                client, "DELETE", base + "/custom_log_parsers/" + name,
                                jwt=jwt, tenant=profile["tenant"], name=name
                            )
                final = read_list(client, base, jwt, profile["tenant"])
                remaining = sum(
                    x.get("parser_name") == name and x.get("cust_id", profile["tenant"]) == profile["tenant"]
                    for x in final
                )
                report["residual_test_parsers"] = remaining
                report["final_count"] = len(final)
                report["cleanup_confirmed"] = remaining == 0
            except (requests.RequestException, SafeAbort, ValueError):
                report["error_type"] = "CleanupVerificationError"
        if owns_client:
            client.close()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Disposable parser pair CRUD verification on the owner-approved POC"
    )
    parser.add_argument("--execute", action="store_true",
                        help="perform owner-approved create, update, delete, and verify cleanup")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: no credentials loaded; no API calls")
        return 0
    try:
        report = run_crud(load_private_profile())
    except (SafeAbort, InvalidSyntheticFixture) as exc:
        print("SAFE_ABORT:", type(exc).__name__, file=sys.stderr)
        return 2

    print(json.dumps(report, sort_keys=True, ensure_ascii=False))
    success = (report["create_http"] == 200 and report["create_confirmed"]
               and report["update_http"] == 200 and report["cleanup_confirmed"])
    print("CRUD_RESULT:", "PASS" if success else
          "PARTIAL_NO_RESIDUE" if report["cleanup_confirmed"] else "INCOMPLETE_CHECK_CLEANUP")
    return 0 if success else 1 if report["cleanup_confirmed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
