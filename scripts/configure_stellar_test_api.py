#!/usr/bin/env python3
"""Interactively store a test Stellar Cyber API profile outside the Git repository.

Never pass an API key as a command-line argument or paste it into chat/logs.
This script does not connect to, modify, or deploy anything to Stellar Cyber.
"""

import argparse
import getpass
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from urllib.parse import urlsplit

CONFIG_FILE = "stellar-test-api.json"


def config_path():
    """Use a per-user location outside the repository, compatible with XDG."""
    xdg_root = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg_root).expanduser() if xdg_root and Path(xdg_root).is_absolute() else Path.home() / ".config"
    return base / "parser-studio" / CONFIG_FILE


def normalize_dp_url(raw_url):
    """Accept a bare HTTPS DP URL or an HTTPS /connect/api/v1 URL."""
    value = raw_url.strip()
    if not value or any(ch.isspace() or ch == "\\" for ch in value):
        raise ValueError("DP 주소에는 공백이나 역슬래시를 사용할 수 없습니다.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("DP 주소 형식이 올바르지 않습니다.") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") not in ("", "/connect/api/v1")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("https://DP-주소 형식만 허용합니다. 경로·계정·쿼리 문자열은 제외하세요.")
    return f"https://{parsed.netloc}"


def validate_credential_fields(cust_id, api_key):
    if not cust_id or cust_id != cust_id.strip() or any(ch.isspace() or ch in "\\/" for ch in cust_id):
        raise ValueError("Tenant ID(cust_id)를 공백 없이 입력하세요.")
    if not api_key or api_key != api_key.strip() or any(ch.isspace() for ch in api_key):
        raise ValueError("API Key만 입력하세요 (Bearer 접두어와 공백 제외).")


def check_directory(directory):
    """Create a private user-owned directory; never silently relax access controls."""
    if directory.is_symlink():
        raise PermissionError("심볼릭 링크 디렉터리는 사용할 수 없습니다.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PermissionError("설정 디렉터리는 현재 사용자 소유이며 권한 0700이어야 합니다.")


def check_existing_file(path):
    """Return whether a safe regular config file exists, rejecting symlinks."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError("기존 설정 파일은 일반 파일·현재 사용자 소유·권한 0600이어야 합니다.")
    return True


def save_config(dp_url, cust_id, api_key, path=None):
    """Atomically write a local test profile; no network calls or secret logging."""
    dp_url = normalize_dp_url(dp_url)
    validate_credential_fields(cust_id, api_key)
    destination = Path(path) if path is not None else config_path()
    old_umask = os.umask(0o077)
    tmp_path = None
    try:
        check_directory(destination.parent)
        check_existing_file(destination)
        handle, name = tempfile.mkstemp(prefix=".stellar-test-api-", suffix=".tmp", dir=destination.parent)
        tmp_path = Path(name)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump({"dp_url": dp_url, "cust_id": cust_id, "api_key": api_key}, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, destination)
        tmp_path = None
        return destination
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)
        os.umask(old_umask)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Stellar Cyber 테스트 API 연결 정보를 안전하게 로컬 저장 (서버 연결 없음)"
    )
    parser.add_argument("--status", action="store_true", help="비밀정보를 출력하지 않고 저장 여부만 확인")
    options = parser.parse_args(argv)
    path = config_path()
    try:
        if options.status:
            if path.parent.exists():
                check_directory(path.parent)
            exists = check_existing_file(path)
            print(f"설정 상태: {'저장됨' if exists else '미설정'} ({path})")
            print("API Key는 표시하지 않습니다.")
            return 0
        if not sys.stdin.isatty():
            print("오류: SSH 등 대화형 터미널에서 직접 실행하세요. API Key를 인자로 전달하지 마세요.", file=sys.stderr)
            return 2
        if path.parent.exists():
            check_directory(path.parent)
        if check_existing_file(path):
            overwrite = input("기존 테스트 API 설정을 교체하시겠습니까? [y/N]: ").strip().lower()
            if overwrite not in ("y", "yes"):
                print("기존 설정을 유지했습니다.")
                return 1
        dp_url = input("Stellar Cyber DP URL (https://...): ").strip()
        cust_id = input("Tenant ID (cust_id): ").strip()
        api_key = getpass.getpass("API Key (입력 내용 숨김): ")
        result = save_config(dp_url, cust_id, api_key, path)
        print(f"테스트 API 연결 정보를 저장했습니다: {result}")
        print("설정 파일: 현재 사용자 전용(0600). 실제 API 호출은 수행하지 않았습니다.")
        return 0
    except (ValueError, OSError, EOFError, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            print("\n입력이 취소됐습니다.", file=sys.stderr)
        else:
            print(f"설정 실패: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
