"""H4 operator-side exact-head evidence under GitHub-enforced branch protection."""
import importlib.util
from pathlib import Path
import unittest

FILE=Path(__file__).resolve().parents[1]/'scripts/verification/h4_exact_head_release_gate.py'
spec=importlib.util.spec_from_file_location('h4_gate',FILE)
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SHA='f'*40
JOBS=[
 'native-isolated-synthetic','web-quality','release-eligibility',
 *(f'Browser regression (shard {i}/6)' for i in range(1,7))
]
def inputs():
    run={'head_sha':SHA,'status':'completed','conclusion':'success',
         'event':'pull_request','run_attempt':1}
    jobs={'total_count':len(JOBS),'jobs':[{'name':n,'status':'completed',
                                  'conclusion':'success','head_sha':SHA} for n in JOBS]}
    artifacts={'artifacts':[{'name':n,'expired':False}
             for n in ('parser-studio-native-evidence',
                       'parser-studio-h2-isolated-native-evidence')]}
    pr={'head':{'sha':SHA},'base':{'ref':'main'},
        'state':'open','draft':False}
    return run,jobs,artifacts,pr
class GateTests(unittest.TestCase):
    def test_all_9_jobs_and_both_artifacts_pass(self):
        gate.validate_release_evidence(*inputs(),expected_sha=SHA)
    def test_active_work_packet_refuses_merge_despite_green_ci(self):
        pending={'state':'open','body':'- [ ] MCV2-C\n- [x] MCV2-A'}
        with self.assertRaisesRegex(ValueError,'ACTIVE_WORK_PACKET'):
            gate.validate_work_packet(pending,[{'total_count':0},{'total_count':0}])
        pending['state']='closed'
        with self.assertRaisesRegex(ValueError,'ACTIVE_WORK_PACKET'):
            gate.validate_work_packet(pending,[{'total_count':0},{'total_count':0}])

    def test_open_p1_and_incomplete_github_search_fail_closed(self):
        closed={'state':'closed','body':'- [x] MCV2-A\n- [x] MCV2-E'}
        for result in ({'total_count':1},{'total_count':0,'incomplete_results':True},{}):
            with self.assertRaisesRegex(ValueError,'OPEN_P0_P1'):
                gate.validate_work_packet(closed,[{'total_count':0},result])
        gate.validate_work_packet(closed,[{'total_count':0},{'total_count':0}])

    def test_wrong_sha_is_rejected(self):
        run,jobs,artifacts,pr=inputs();run['head_sha']='a'*40
        with self.assertRaisesRegex(ValueError,'HEAD_SHA'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_job_failure_is_rejected(self):
        run,jobs,artifacts,pr=inputs();jobs['jobs'][1]['conclusion']='failure'
        with self.assertRaisesRegex(ValueError,'REQUIRED_JOBS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_missing_release_eligibility_rejected(self):
        run,jobs,artifacts,pr=inputs()
        jobs['jobs']=[item for item in jobs['jobs'] if item['name']!='release-eligibility']
        jobs['total_count']=len(jobs['jobs'])
        with self.assertRaisesRegex(ValueError,'REQUIRED_JOBS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_failing_release_eligibility_rejected(self):
        run,jobs,artifacts,pr=inputs()
        next(item for item in jobs['jobs'] if item['name']=='release-eligibility')['conclusion']='failure'
        with self.assertRaisesRegex(ValueError,'REQUIRED_JOBS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_missing_browser_shard_rejected(self):
        run,jobs,artifacts,pr=inputs();jobs['jobs'].pop()
        with self.assertRaisesRegex(ValueError,'REQUIRED_JOBS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_missing_native_artifact_rejected(self):
        run,jobs,artifacts,pr=inputs();artifacts['artifacts'].pop()
        with self.assertRaisesRegex(ValueError,'NATIVE_ARTIFACTS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_draft_or_wrong_base_rejected(self):
        run,jobs,artifacts,pr=inputs();pr['draft']=True
        with self.assertRaisesRegex(ValueError,'PR_NOT_REVIEWABLE'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
        pr['draft']=False;pr['base']['ref']='release'
        with self.assertRaisesRegex(ValueError,'MAIN_BASE'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_stale_or_expired_evidence_rejected(self):
        run,jobs,artifacts,pr=inputs();artifacts['artifacts'][0]['expired']=True
        with self.assertRaisesRegex(ValueError,'NATIVE_ARTIFACTS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
    def test_extra_unexpected_job_prevents_false_green(self):
        run,jobs,artifacts,pr=inputs()
        jobs['jobs'].append({'name':'unexpected','status':'completed','conclusion':'success'})
        jobs['total_count']=10
        with self.assertRaisesRegex(ValueError,'REQUIRED_JOBS'):
            gate.validate_release_evidence(run,jobs,artifacts,pr,expected_sha=SHA)
if __name__=='__main__': unittest.main()
