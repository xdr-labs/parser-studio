"""Conservative partial lexical-atom recovery."""
import unittest

from generic_partial_atoms import augment_incomplete_atoms
from security_source import parse_security_source
from source_parse import assert_source_accounting


class GenericPartialAtomTests(unittest.TestCase):
    def test_network_url_hash_atoms_are_exact_but_event_stays_partial(self):
        sha='a'*64
        raw=(
            'Alert from 192.0.2.10:443 to 198.51.100.20/53 '
            'see https://example.test/a?q=1 digest '+sha+' trailing prose'
        )
        base=parse_security_source(raw)
        event=augment_incomplete_atoms(base);assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        self.assertIn('GENERIC_ATOMS',event.syntax)
        atoms=event.vendor_fields['generic_atoms']
        self.assertEqual(
            ['192.0.2.10:443','198.51.100.20/53'],atoms['network']
        )
        self.assertEqual(['https://example.test/a?q=1'],atoms['url'])
        self.assertEqual([sha],atoms['sha256'])
        data=raw.encode()
        for span in event.value_spans:
            if span.path.startswith('generic_atoms.'):
                value=data[span.start_byte:span.end_byte].decode()
                self.assertIn(value,sum(atoms.values(),[]))

    def test_existing_value_span_blocks_nested_atom_duplication(self):
        raw='url="https://example.test/a" other=ok third=yes fourth=yes fifth=yes'
        base=parse_security_source(raw)
        self.assertEqual('SOURCE_PARSED',base.status)
        self.assertIs(base,augment_incomplete_atoms(base))

    def test_invalid_ip_and_port_are_not_atoms(self):
        raw='Alert 999.999.999.999 and 192.0.2.1:70000 remain prose'
        event=augment_incomplete_atoms(parse_security_source(raw))
        self.assertNotIn('generic_atoms',event.vendor_fields)

    def test_atoms_never_remove_existing_spans_or_raw(self):
        raw='NOTICE prefix user=Zoë action=allow peer 192.0.2.7 trailing prose'
        base=parse_security_source(raw)
        event=augment_incomplete_atoms(base)
        self.assertEqual(raw,event.raw)
        old={(s.path,s.start_byte,s.end_byte) for s in base.value_spans}
        new={(s.path,s.start_byte,s.end_byte) for s in event.value_spans}
        self.assertTrue(old<=new)
        self.assertNotEqual('SOURCE_PARSED',event.status)


if __name__=='__main__':
    unittest.main()
