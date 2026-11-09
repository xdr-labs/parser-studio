"""Independent TS/Python semantic-port-source contract; fixed negative truths."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'runtime' / 'multipass'))
from stellar_dictionary import _explicit_port_target


class PortIdentity(unittest.TestCase):
    def test_no_translated_field_becomes_original_port(self):
        for source in (
            'nat.source-port','nat_source.source-port','post_nat.source-port',
            'translated_source.source-port','source_nat.source-port',
            'postNat.source-port','sourceTranslation.source-port',
            'snat.source-port','dnat.source-port',
            'pre-nat.destination-port',
            'network_address_translation.destination-port',
        ):
            with self.subTest(source=source):
                self.assertIsNone(_explicit_port_target(source))

    def test_literal_source_port_survives(self):
        self.assertEqual(_explicit_port_target('syslog_sd.element_1.params.source-port'),'srcport')
        self.assertEqual(_explicit_port_target('syslog_sd.element_1.params.destination-port'),'dstport')
        self.assertEqual(_explicit_port_target('national.source-port'),'srcport')


if __name__ == '__main__':
    unittest.main()
