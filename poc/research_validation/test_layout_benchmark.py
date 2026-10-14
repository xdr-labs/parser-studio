"""Independent H2r source-reference and split-accounting tests."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import benchmark_layout as bench


class LayoutBenchmarkTests(unittest.TestCase):
    def test_source_scalars_and_byte_spans_are_not_normalized(self):
        raw = '000123 caf\u00e9 - 2001:db8::1'
        probe = bench.flow_reference(raw)
        self.assertEqual([v for _,v,_,_ in probe.fields], ['000123','caf\u00e9','-','2001:db8::1'])
        for _,value,a,b in probe.fields:
            self.assertEqual(raw.encode()[a:b].decode(),value)

    def test_empty_cells_are_not_silently_dropped(self):
        probe = bench.flow_reference('1  2 ')
        self.assertEqual([v for _,v,_,_ in probe.fields], ['1','','2',''])
        self.assertEqual(len(probe.fields),4)

    def test_global_hash_split_preserves_cross_file_duplicates(self):
        with tempfile.TemporaryDirectory(prefix='parser-layout-split-') as directory:
            root=Path(directory)
            families={'a.log':[f'{i} 100 200 allow' for i in range(8)],
                      'b.log':[f'{i} 100 200 allow' for i in range(4,12)]}
            files=[]
            for name,rows in families.items():
                content=('\n'.join(rows)+'\n').encode();(root/name).write_bytes(content)
                files.append({'local_name':name,'sha256':hashlib.sha256(content).hexdigest()})
            (root/'manifest.json').write_text(json.dumps({'files':files}))
            with patch.object(bench,'FLOW',root):
                batches,groups,_=bench.flow_batches()
            train={r for g in groups.values() for r in g['train']}
            test={r for g in groups.values() for _,r in g['heldout']}
            self.assertFalse(train & test)
            self.assertEqual(sum(len(g['train'])+len(g['heldout']) for g in groups.values()),16)
            self.assertEqual(sum(len(b['raws']) for b in batches),sum(len(g['heldout']) for g in groups.values()))

if __name__=='__main__':unittest.main()
