"""Bounded, read-only recovery verification for a failed preview installation."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'ops/preview-domain/check-staged-files.sh'

class StagingRecovery(unittest.TestCase):
    def test_fresh_exact_reuse_and_fail_closed_variants(self):
        with tempfile.TemporaryDirectory(prefix='parser-staging-recovery-') as path:
            base=Path(path)
            pkg=base/'qualified'
            site=base/'site'
            backend=base/'backend'
            parser=base/'parser'
            for kind in ('web','backend','multipass'):
                (pkg/kind).mkdir(parents=True)
                (pkg/kind/'sample.bin').write_bytes((kind+'-v1').encode())
            def run():
                return subprocess.run(
                    ['bash',str(HELPER),str(pkg),str(site),str(backend),str(parser)],
                    capture_output=True,text=True,timeout=10)
            result=run()
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'FRESH')

            # Incomplete previous installation is never treated as safe.
            site.mkdir()
            self.assertNotEqual(run().returncode,0)
            backend.mkdir()
            parser.mkdir()
            for kind,dst in (('web',site),('backend',backend),('multipass',parser)):
                (dst/'sample.bin').write_bytes((kind+'-v1').encode())
            result=run()
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'REUSE_VERIFIED')

            cache=parser/'__pycache__'
            cache.mkdir()
            (cache/'sample.pyc').write_bytes(b'python local import cache')
            self.assertEqual(run().stdout.strip(),'REUSE_VERIFIED')
            (site/'sample.bin').write_bytes(b'different bytes')
            self.assertNotEqual(run().returncode,0)
            (site/'sample.bin').write_bytes(b'web-v1')
            (backend/'unexpected').write_text('unreviewed source')
            self.assertNotEqual(run().returncode,0)
            (backend/'unexpected').unlink()
            (backend/'dangerous-link').symlink_to(site/'sample.bin')
            self.assertNotEqual(run().returncode,0)

if __name__=='__main__':
    unittest.main()
