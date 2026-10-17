#!/usr/bin/env python3
"""Pin a third-party Syslog conformance suite before candidate observation."""
from pathlib import Path
import hashlib, json, os
from urllib.request import urlopen, Request

STATE = Path.home() / ".local/state/parserstudio-syslogng-independent-20261017"
PUBLIC = Path(__file__).with_name("syslogngIndependentSource.pinned.json")
REPO = "syslog-ng/syslog-ng"
REVISION = "fddad8aaad25f008d49e8fb30d018946941c2414"
SOURCE = "modules/syslogformat/tests/test_syslog_format.c"


def write_once(path: Path, data: bytes) -> None:
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError("Previously pinned source has changed")
        return
    handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "wb") as f:
        f.write(data)


def main() -> None:
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    url = f"https://raw.githubusercontent.com/{REPO}/{REVISION}/{SOURCE}"
    request = Request(url, headers={"User-Agent":"ParserStudio-Independent-Syslog-Source"})
    with urlopen(request,timeout=22) as response:
        raw = response.read(1024*1024+1)
    if not raw or len(raw)>1024*1024:
        raise RuntimeError("Out-of-bounds conformance source")
    write_once(STATE/"upstream-original.c",raw)
    provenance = {
      "schema": "new-independent-syslog-ng-source-v1",
      "stage": "PINNED_BEFORE_CANDIDATE_SCORING",
      "repo":REPO,"revision":REVISION,"source_path":SOURCE,
      "byte_count":len(raw),"original_sha256":hashlib.sha256(raw).hexdigest(),
      "licensing": "PUBLIC_TEST_SOURCE_LICENSE_NOT_INDEPENDENTLY_CERTIFIED",
      "distinct_from_prior_repos": True,
      "holdout_source_data":"private_0600_not_in_git",
      "source_expected_values":"upstream_C_assertions_only_if_unambiguous",
      "original_hardware_packet":False,
    }
    content=(json.dumps(provenance,indent=2)+"\n").encode()
    write_once(STATE/"source.pinned.json",content)
    if PUBLIC.exists() and PUBLIC.read_bytes()!=content:
        raise RuntimeError("Published provenance cannot change")
    PUBLIC.write_bytes(content)
    print(json.dumps({"frozen":True,"files":1,"bytes":len(raw),
                      "source_sha256":provenance["original_sha256"]}))


if __name__ == "__main__":
    main()
