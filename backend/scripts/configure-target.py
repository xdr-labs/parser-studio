#!/usr/bin/env python3
"""Interactive, offline, owner-only DP and Sensor profile setup.

Run on a trusted SSH terminal; no CLI secret arguments, environment secrets,
HTTP calls, deployment, telemetry or log content. Python stdlib only.

Profile (outside all repository worktrees):
  ~/.parser-studio-secrets/connection.json

The normal backend does NOT auto-read this file or enable network features.
A separately approved in-network backend service must authenticate the
operator, protect credentials, and verify DP/sensor ownership before use.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit

SCHEMA = "parser-studio.target-connection.v0.1"
BACKEND = Path(__file__).resolve().parents[1]
# The dev-atlas Parser Studio checkout and backend/.tmp use shared 0775
# development permissions. Never place plaintext API Keys there. Store
# operator-only secrets directly under the owner-controlled home directory.
# This path is independent of the working directory and outside Git.
PARENT = Path.home()
PRIVATE_DIR = PARENT / ".parser-studio-secrets"
PROFILE_PATH = PRIVATE_DIR / "connection.json"
MAX_PROFILE_BYTES = 16 * 1024
TENANT = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class ProfileError(Exception):
    """Only a fixed error code is shown; never interpolates input or secrets."""


def fail(code: str) -> None:
    raise ProfileError(code)


def validate_url(raw: str) -> str:
    if not isinstance(raw, str) or not raw or raw != raw.strip():
        fail("DP_URL_INVALID")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
        hostname = parsed.hostname
    except (ValueError, TypeError):
        fail("DP_URL_INVALID")
    if (parsed.scheme != "https" or not hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")
            or (port is not None and not 1 <= port <= 65535)):
        fail("DP_URL_INVALID")
    if ("@" in parsed.netloc or any(c.isspace() for c in raw)
            or any(ord(c) < 33 for c in raw)):
        fail("DP_URL_INVALID")
    host_unbracketed = hostname.strip("[]")
    try:
        ipaddress.ip_address(host_unbracketed)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and (not HOST.fullmatch(host_unbracketed)
                      or ".." in host_unbracketed or hostname.lower() == "localhost"):
        fail("DP_URL_INVALID")
    if not is_ip and host_unbracketed.startswith("-"):
        fail("DP_URL_INVALID")
    # URL is a locator only, not an authorization to connect or deploy.
    return parsed.geturl().rstrip("/")


def validate_sensor_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw)
    except (ValueError, TypeError):
        fail("SENSOR_IP_INVALID")
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback or getattr(addr, "is_link_local", False):
        fail("SENSOR_IP_INVALID")
    if addr.version == 4 and str(addr) == "255.255.255.255":
        fail("SENSOR_IP_INVALID")
    return str(addr)


def validate_port(value: object, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        fail("PORT_INVALID")
    if optional and value < 1024:
        fail("PARSER_PORT_PRIVILEGED")
    return value


def validate_profile(profile: object) -> dict:
    if not isinstance(profile, dict) or set(profile) != {
        "schema", "dp", "sensor", "parser", "deployment"
    }:
        fail("PROFILE_INVALID")
    if profile["schema"] != SCHEMA:
        fail("PROFILE_INVALID")
    dp, sensor, parser, deployment = (
        profile["dp"], profile["sensor"], profile["parser"], profile["deployment"]
    )
    if not isinstance(dp, dict) or set(dp) != {"url", "tenant_id", "api_key"}:
        fail("PROFILE_INVALID")
    if not isinstance(sensor, dict) or set(sensor) != {"ip", "port", "protocol"}:
        fail("PROFILE_INVALID")
    if not isinstance(parser, dict) or set(parser) != {"preferred_listener_port", "port_verified"}:
        fail("PROFILE_INVALID")
    if deployment != {"automatic_apply_enabled": False}:
        fail("PROFILE_INVALID")
    validate_url(dp["url"])
    if not isinstance(dp["tenant_id"], str) or not TENANT.fullmatch(dp["tenant_id"]):
        fail("TENANT_INVALID")
    key = dp["api_key"]
    if (not isinstance(key, str) or not 1 <= len(key) <= 8192
            or any(c in key for c in "\r\n\0")):
        fail("KEY_INVALID")
    validate_sensor_ip(sensor["ip"])
    validate_port(sensor["port"])
    if sensor["protocol"] not in ("udp", "tcp"):
        fail("SENSOR_PROTOCOL_INVALID")
    requested_listener = validate_port(parser["preferred_listener_port"], optional=True)
    # Legacy profiles allowed "no preference"; this means the SAME
    # sensor ingress/CONF source port, not a second unknown port.
    if requested_listener is not None and requested_listener != sensor["port"]:
        fail("SENSOR_PARSER_PORT_MISMATCH")
    if parser["port_verified"] is not False:
        fail("PROFILE_INVALID")
    raw = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_PROFILE_BYTES:
        fail("PROFILE_TOO_LARGE")
    return profile


def _check_directory(path: Path, *, private: bool) -> bool:
    try:
        item = path.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid()
            or stat.S_ISLNK(item.st_mode)):
        fail("DIRECTORY_UNSAFE")
    # The owning home directory can be 0750/0755, but must not be writable
    # by group/others. The dedicated secret directory MUST be 0700.
    if item.st_mode & (0o077 if private else 0o022):
        fail("DIRECTORY_UNSAFE")
    return True


def ensure_storage() -> None:
    if not _check_directory(PARENT, private=False):
        PARENT.mkdir(mode=0o700)
        _check_directory(PARENT, private=False)
    if not _check_directory(PRIVATE_DIR, private=True):
        PRIVATE_DIR.mkdir(mode=0o700)
        _check_directory(PRIVATE_DIR, private=True)


def _check_file() -> bool:
    try:
        item = PROFILE_PATH.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode)
            or item.st_uid != os.getuid() or item.st_nlink != 1
            or item.st_mode & 0o077 or item.st_size > MAX_PROFILE_BYTES):
        fail("FILE_UNSAFE")
    return True


def read_profile() -> dict | None:
    if not _check_directory(PARENT, private=False):
        return None
    if not _check_directory(PRIVATE_DIR, private=True):
        return None
    if not _check_file():
        return None
    if not hasattr(os, "O_NOFOLLOW"):
        fail("NOFOLLOW_UNAVAILABLE")
    fd = os.open(PROFILE_PATH, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        item = os.fstat(fd)
        if (not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid()
                or item.st_nlink != 1 or item.st_mode & 0o077
                or item.st_size > MAX_PROFILE_BYTES):
            fail("FILE_UNSAFE")
        data = os.read(fd, MAX_PROFILE_BYTES + 1)
        if len(data) > MAX_PROFILE_BYTES:
            fail("PROFILE_TOO_LARGE")
        try:
            parsed = json.loads(data.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeDecodeError):
            fail("PROFILE_INVALID")
        return validate_profile(parsed)
    finally:
        os.close(fd)


def save_profile(profile: dict, *, replace: bool = False) -> None:
    validate_profile(profile)
    ensure_storage()
    exists = _check_file()
    if exists and not replace:
        fail("EXISTING_PROFILE_REQUIRES_CONFIRMATION")
    contents = (json.dumps(profile, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(contents) > MAX_PROFILE_BYTES:
        fail("PROFILE_TOO_LARGE")
    # Atomic replace in the same 0700 directory; never follow destination
    # symlinks or overwrite hardlinks/unsafe files.
    temporary: str | None = None
    fd = -1
    try:
        fd, temporary = tempfile.mkstemp(prefix=".connection-", suffix=".tmp",
                                          dir=PRIVATE_DIR)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(contents)
            output.flush()
            os.fsync(fd)
        os.close(fd)
        fd = -1
        _check_file()  # Reject an unexpected target file change pre-rename.
        # Do not allow an unreviewed file appearing during initial setup.
        if not exists and PROFILE_PATH.exists():
            fail("FILE_UNSAFE")
        os.replace(temporary, PROFILE_PATH)
        temporary = None
        folder_fd = os.open(PRIVATE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def prompt_profile(input_fn=input, secret_fn=getpass.getpass) -> dict:
    print("Parser Studio — 테스트 DP / Modular Sensor 연결정보 저장", flush=True)
    print("연결·배포·로그 전송은 수행되지 않습니다.", flush=True)
    dp_url = validate_url(input_fn("DP HTTPS URL (예: https://dp.example.local): ").strip())
    tenant = input_fn("Tenant ID: ").strip()
    if not TENANT.fullmatch(tenant):
        fail("TENANT_INVALID")
    key = secret_fn("DP User Scope API Key (입력 숨김): ")
    sensor_ip = validate_sensor_ip(input_fn("Modular Sensor IP: ").strip())
    sensor_port_raw = input_fn("센서 로그 수신 포트: ").strip()
    if not sensor_port_raw.isdecimal():
        fail("PORT_INVALID")
    sensor_port = validate_port(int(sensor_port_raw))
    protocol = input_fn("전송 프로토콜 [udp/tcp]: ").strip().lower()
    # Exactly one receiver port: it is used both as the sensor's log
    # destination and as the generated Fluentd CONF <source> port.
    parser_port = sensor_port
    value = {
        "schema": SCHEMA,
        "dp": {"url": dp_url, "tenant_id": tenant, "api_key": key},
        "sensor": {"ip": sensor_ip, "port": sensor_port, "protocol": protocol},
        "parser": {"preferred_listener_port": parser_port, "port_verified": False},
        "deployment": {"automatic_apply_enabled": False},
    }
    return validate_profile(value)


def redacted_status() -> int:
    """Verify the existing private configuration without printing its values."""
    profile = read_profile()
    if profile is None:
        print("PROFILE_NOT_CONFIGURED")
        return 1
    print("PROFILE_VALID_PRIVATE: DP, Tenant, API Key and Sensor configured; key hidden.")
    print("Automatic deployment: DISABLED. Sensor/parser verification: NOT VERIFIED.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline secure DP/Sensor profile setup")
    parser.add_argument("--check", action="store_true", help="Verify stored profile without displaying values")
    opts = parser.parse_args()
    try:
        if opts.check:
            return redacted_status()
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            fail("INTERACTIVE_TTY_REQUIRED")
        previous = read_profile()
        if previous is not None:
            confirm = input("이미 저장된 설정이 있습니다. 전체 교체할까요? [yes/no]: ")
            if confirm.strip().lower() != "yes":
                print("변경하지 않았습니다.")
                return 0
        profile = prompt_profile()
        save_profile(profile, replace=previous is not None)
        print("저장 완료: " + str(PROFILE_PATH))
        print("권한: 디렉터리 0700, 파일 0600. API Key는 표시하지 않습니다.")
        print("실제 DP 연결·센서 전송·파서 배포는 수행하지 않았습니다.")
        return 0
    except (ProfileError, KeyboardInterrupt, EOFError) as exc:
        code = str(exc) if isinstance(exc, ProfileError) else "CANCELLED"
        print("PROFILE_SETUP_" + code, file=sys.stderr)
        return 2
    except OSError:
        print("PROFILE_SETUP_FILESYSTEM_UNAVAILABLE", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
