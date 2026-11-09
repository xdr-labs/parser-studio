"""Release blocker is enforced on main, but remediation PRs remain mergeable."""
import os
import re
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=(ROOT/'.github/workflows/quality.yml').read_text(encoding='utf-8')
SECTION=WORKFLOW.split('  release-eligibility:',1)[1].split('  native-isolated-synthetic:',1)[0]
BLOCK=re.search(r'(?m)^        run: \|\n((?:(?:          .*|)\n)+)',
    SECTION.split('      - name: Reject any open P0 or P1 issue before merge',1)[1])
assert BLOCK, 'Release eligibility workflow script changed'
SCRIPT=textwrap.dedent(BLOCK.group(1))

class ActualReleaseGateTests(unittest.TestCase):
    def run_gate(self,event,blocker):
        with tempfile.TemporaryDirectory() as tmp:
            tool=Path(tmp)/'gh'
            tool.write_text('#!/bin/sh\n'
                'case "$*" in *labels=P1*) [ "$SIMULATE_OPEN_P1" = "1" ] && echo 285 ;; esac\n'
                'exit 0\n',encoding='utf-8')
            tool.chmod(0o755)
            env={**os.environ,'PATH':tmp+os.pathsep+os.environ.get('PATH',''),
                 'GITHUB_EVENT_NAME':event,'GH_REPO':'xdr-labs/parser-studio',
                 'GH_TOKEN':'synthetic-test-only','SIMULATE_OPEN_P1':'1' if blocker else '0'}
            return subprocess.run(['bash','-e','-o','pipefail','-c',SCRIPT],
                env=env,text=True,capture_output=True,timeout=5,check=False)

    def test_open_p1_does_not_prevent_verified_remediation_pr(self):
        result=self.run_gate('pull_request',True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('H4_RELEASE_ELIGIBILITY_NOT_EVALUATED_ON_PR',result.stdout)
        self.assertNotIn('H4_OPEN_P0_P1_GATE_PASS',result.stdout)

    def test_open_p1_blocks_main_and_manual_release(self):
        for event in ('push','workflow_dispatch'):
            with self.subTest(event=event):
                result=self.run_gate(event,True)
                self.assertNotEqual(result.returncode,0,result.stdout)
                self.assertIn('H4_RELEASE_BLOCKED_OPEN_P1=285',result.stdout)

    def test_no_blockers_allows_main_release_eligibility(self):
        result=self.run_gate('push',False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('H4_OPEN_P0_P1_GATE_PASS',result.stdout)

if __name__=='__main__': unittest.main()
