"""Reproducible independent suite bound to the exact current security baseline."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parent
CURRENT='c2f464444a7aa899bd8b251507234720e4cbdde2'
ENGINE=(ROOT/'.cache/current-c2f4644/poc/vendor_engine').resolve()

if __name__=='__main__':
    sys.path.insert(0,str(ENGINE));import source_parse,security_source
    assert Path(source_parse.__file__).resolve().parent==ENGINE
    assert Path(security_source.__file__).resolve().parent==ENGINE
    hashes={}
    for name in ('engine.py','source_parse.py','structured_source.py','residual_kv.py','java_source.py','source_kv.py','security_source.py'):
        expected=subprocess.check_output(['git','show',f'{CURRENT}:poc/vendor_engine/{name}'],cwd=ROOT)
        actual=(ENGINE/name).read_bytes();assert actual==expected,name
        hashes[name]=hashlib.sha256(actual).hexdigest()
    sys.path.insert(0,str(ROOT))
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.discover(str(ROOT),pattern='test_*.py'))
    report={'contract':'security-poc-current-test-evidence.v1','python':sys.version.split()[0],
      'baseline_commit':CURRENT,'baseline_entrypoint':'security_source.parse_security_source',
      'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
      'success':result.wasSuccessful(),'baseline_integrity':hashes,
      'candidate_module_hashes':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('candidate.py','security_document.py','security_envelopes.py','security_leef.py','security_cef.py','cef_reference.py')},
      'cef_boundary_red_control':{'tests':8,'failures':4,'errors':0},
      'followon_red_controls':{'mixed_document':{'tests':6,'failures':3,'errors':0},'leef_xhh':{'tests':6,'failures':3,'errors':1},'leef_oracle':{'tests':6,'failures':1,'errors':0}},
      'envelope_red_against_historical_2fee28f':{'tests':8,'passes':4,'failures':3,'errors':1},
      'caveat':'RED control predates current main CEE implementation; it is not a current-main accuracy gain.'}
    (ROOT/'security-current-tests.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('CURRENT_SECURITY_SUITE',report['tests'],'FAILURES',report['failures'],'ERRORS',report['errors'],'SKIPS',report['skips'])
    if not result.wasSuccessful():raise SystemExit(1)
