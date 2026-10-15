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

    def test_ipv6_dotted_mac_and_uuid_are_validated_source_atoms(self):
        raw=(
            'Alert 2001:db8::10 device 0200.0000.0001 '
            'session 123e4567-e89b-12d3-a456-426614174000 trailing prose'
        )
        event=augment_incomplete_atoms(parse_security_source(raw))
        assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        atoms=event.vendor_fields['generic_atoms']
        self.assertIn('2001:db8::10',atoms['network'])
        self.assertIn('0200.0000.0001',atoms['mac'])
        self.assertIn(
            '123e4567-e89b-12d3-a456-426614174000',atoms['uuid']
        )

    def test_invalid_ipv6_dotted_mac_and_uuid_are_not_atoms(self):
        raw=(
            'Alert 2001:::bad device 0200.0000.00ZZ '
            'session 123e4567-e89b-12d3-a456-zzzzzzzzzzzz prose'
        )
        event=augment_incomplete_atoms(parse_security_source(raw))
        atoms=event.vendor_fields.get('generic_atoms',{})
        self.assertNotIn('network',atoms)
        self.assertNotIn('mac',atoms)
        self.assertNotIn('uuid',atoms)

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
