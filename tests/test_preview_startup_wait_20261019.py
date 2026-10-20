"""Check that service startup is retried without actual root/systemd operations."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
INSTALLER=(ROOT/'ops/preview-domain/install-private-preview.sh').read_text()

def readiness_function():
    return 'wait_for_service() {' + INSTALLER.split('wait_for_service() {',1)[1].split('\n}\n',1)[0] + '\n}\n'

class ServiceStartupWait(unittest.TestCase):
    def test_retries_cold_start_until_health_endpoint_is_ready(self):
        body=readiness_function()
        script=body + '''
            counter=0
            curl(){ counter=$((counter+1)); test "$counter" -ge 4; }
            systemctl(){ return 0; }
            sleep(){ :; }
            wait_for_service service-demo http://127.0.0.1:4304/health
            test "$counter" -eq 4
        '''
        result=subprocess.run(['bash','-c',script],capture_output=True,text=True,timeout=6)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('ready after probe 4',result.stdout)

    def test_stops_when_service_is_inactive_without_faking_success(self):
        body=readiness_function()
        script=body+'''
            counter=0
            curl(){ counter=$((counter+1)); return 7; }
            systemctl(){
              if [[ "$1" == "is-active" ]]; then return 3; fi
              return 0
            }
            journalctl(){ :; }
            sleep(){ :; }
            if wait_for_service service-demo http://127.0.0.1:4304/health; then exit 10; fi
            test "$counter" -eq 1
        '''
        result=subprocess.run(['bash','-c',script],capture_output=True,text=True,timeout=6)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_has_finite_timeout_when_healthy_never_arrives(self):
        body=readiness_function()
        script=body+'''
            counter=0
            curl(){ counter=$((counter+1)); return 7; }
            systemctl(){ return 0; }
            journalctl(){ :; }
            sleep(){ :; }
            if wait_for_service service-demo http://127.0.0.1:4304/health; then exit 10; fi
            test "$counter" -eq 40
        '''
        result=subprocess.run(['bash','-c',script],capture_output=True,text=True,timeout=6)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':
    unittest.main()
