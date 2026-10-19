"""Regression coverage for Nginx asynchronous TLS virtual-host reload.

Exercises the exact installer readiness function with a scripted sequence
representing old default-host TLS identity before the new host is active.
Never changes public Nginx or the system TLS trust configuration.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'ops/preview-domain/install-private-preview.sh').read_text()

def readiness_function():
    return ("wait_for_domain_route() {" +
            SOURCE.split('wait_for_domain_route() {', 1)[1].split('\n}\n', 1)[0] +
            '\n}\n')

class NginxReloadReadiness(unittest.TestCase):
    def simulate(self, scenario):
        with tempfile.TemporaryDirectory(prefix='parser-nginx-reload-') as temp:
            counter = Path(temp) / 'count'
            counter.write_text('0')
            script = readiness_function() + r'''
SITE=app.parser.xdr.ooo
curl() {
  [[ "$*" == *"--noproxy *"* && "$*" == *"--resolve "* ]] || return 92
  [[ "$*" != *" -k"* && "$*" != *"--insecure"* ]] || return 93
  if [[ "$*" == *"https://$SITE/"* ]]; then
    local n
    n=$(cat "$COUNT_FILE")
    if [[ "$SIM_MODE" == old_cert_then_ready && "$n" -lt 3 ]]; then
      return 60
    fi
    if [[ "$SIM_MODE" == always_wrong_certificate ]]; then
      return 60
    fi
    if [[ "$SIM_MODE" == wrong_site_content ]]; then
      printf '<title>Stellar Cyber Data Exporter</title>\n__PARSER_HTTP_CODE__200'
      return 0
    fi
    printf '<title>Parser Studio</title>\n__PARSER_HTTP_CODE__200'
  else
    local n
    n=$(cat "$COUNT_FILE")
    n=$((n+1))
    printf '%s\n' "$n" > "$COUNT_FILE"
    if [[ "$SIM_MODE" == old_cert_then_ready && "$n" -eq 1 ]]; then
      printf 404
    else
      printf 301
    fi
  fi
}
sleep() { :; }
if wait_for_domain_route; then
  printf 'ACCEPTED\n'
else
  printf 'REJECTED\n'
  exit 1
fi
'''
            env = {**os.environ, 'COUNT_FILE': str(counter), 'SIM_MODE': scenario}
            result = subprocess.run(['bash', '-c', script], env=env,
                                    capture_output=True, text=True, timeout=15)
            return result, int(counter.read_text())

    def test_transient_old_exporter_certificate_and_404_are_retried(self):
        result, probes = self.simulate('old_cert_then_ready')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(probes, 3)
        self.assertIn('hostname validation after probe 3', result.stdout)

    def test_wrong_tls_certificate_is_never_accepted(self):
        result, probes = self.simulate('always_wrong_certificate')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(probes, 40)
        self.assertIn('HTTPS=TLS_OR_TRANSPORT_ERROR', result.stderr)

    def test_wrong_vhost_body_is_never_accepted(self):
        result, probes = self.simulate('wrong_site_content')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(probes, 40)

    def test_transport_probes_never_bypass_certificate_or_hostname(self):
        fn = readiness_function()
        self.assertIn('--noproxy', fn)
        self.assertIn('--resolve "$SITE:443:127.0.0.1"', fn)
        self.assertIn('https://$SITE/', fn)
        self.assertNotIn('curl -k', fn)
        self.assertNotIn('curl --insecure', fn)

if __name__ == '__main__':
    unittest.main()
