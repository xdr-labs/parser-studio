import unittest
from port_inventory import propose_from_ports

class PortInventoryTests(unittest.TestCase):
    def test_skip_union_and_choose_next_candidate(self):
        x=propose_from_ports([20000,20003],[20000,20001,20005])
        self.assertEqual(x['candidate'],20002)
        self.assertEqual(x['status'],'CANDIDATE_REQUIRES_TARGET_RECHECK')
        self.assertFalse(x['reserved'])
    def test_known_conflict(self):
        x=propose_from_ports([6800],[20000,21000],requested=6800)
        self.assertEqual(x['status'],'KNOWN_COLLISION')
        self.assertFalse(x['reserved'])
    def test_safe_override_is_only_provisional(self):
        x=propose_from_ports([20000],[20001],requested=23567)
        self.assertEqual(x['candidate'],23567)
        self.assertEqual(x['status'],'CANDIDATE_REQUIRES_TARGET_RECHECK')
    def test_bad_or_incomplete_evidence_never_claims_free(self):
        for bad in [[True],[None],['20000'],[0],[65536]]:
            with self.subTest(port=bad):
                self.assertEqual(propose_from_ports(bad,[20000])['status'],'INCOMPLETE_EVIDENCE')
    def test_invalid_override_not_a_port(self):
        self.assertEqual(propose_from_ports([],[20001],requested=80)['status'],'INVALID_OVERRIDE')
    def test_full_range_returns_no_candidate(self):
        x=propose_from_ports(list(range(20000,26000)),list(range(26000,30001)))
        self.assertEqual(x['status'],'NO_CANDIDATE')

if __name__=='__main__':unittest.main()
