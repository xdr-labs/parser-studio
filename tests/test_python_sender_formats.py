#!/usr/bin/env python3
"""Offline stdlib-only source grammar and fresh-value regression of the downloadable sender."""
from __future__ import annotations

import ast
import csv
import datetime as dt
import io
import json
import runpy
import unittest
from unittest import mock
from pathlib import Path

TEMPLATE=Path(__file__).resolve().parents[1] / "src/guided/pythonTestSenderTemplate.py"
runtime=runpy.run_path(str(TEMPLATE))
update=runtime["update_record"]
CITIES={"Seoul","Tokyo","London","Toronto","Paris","Singapore"}

class PythonSenderFormatTests(unittest.TestCase):
    def test_stdlib_only_and_no_eager_network(self):
        tree=ast.parse(TEMPLATE.read_text())
        sources={node.names[0].name.split(".")[0] for node in ast.walk(tree)
                 if isinstance(node,ast.Import)}
        self.assertEqual(sources,
            {"base64","csv","datetime","io","ipaddress","json","re","secrets",
             "socket","sys","time"})
        self.assertFalse(any(isinstance(node,ast.ImportFrom) and node.module not in {"__future__"}
                             for node in ast.walk(tree)))

    def test_json_timestamp_and_identifiers(self):
        row='{"timestamp":"2020-10-17T11:12:13Z","src_ip":"192.0.2.10","email":"alice@example.test","username":"alice","location":"Seoul","other":42}'
        a=json.loads(update(row,{"format":"json"}))
        self.assertEqual(a["other"],42)
        self.assertNotEqual(a["username"],"alice")
        self.assertTrue(a["username"].startswith("user"))
        self.assertTrue(a["email"].endswith("@example.test"))
        self.assertIn(a["location"],CITIES)
        self.assertNotEqual(a["src_ip"],"192.0.2.10")
        self.assertLess(abs((dt.datetime.now(dt.timezone.utc)-
            dt.datetime.fromisoformat(a["timestamp"].replace("Z","+00:00"))).total_seconds()),5)

    def test_syslog_rfc3164_quoted_kv(self):
        s='<134>Oct  3 01:02:03 firewall action=deny srcip="192.0.2.10" user="alice"'
        a=update(s,{"format":"syslog_rfc3164"})
        prefix='<134>'+dt.datetime.now().strftime("%b")+f" {dt.datetime.now().day:2d} "
        self.assertTrue(a.startswith(prefix),a)
        self.assertIn("firewall action=deny",a)
        self.assertIn('srcip="',a)
        self.assertIn('user="user',a)

    def test_rfc5424_fractional_timezone(self):
        s='<165>1 2020-10-17T11:12:13.000Z host app - - - src=192.0.2.7'
        a=update(s,{"format":"syslog_rfc5424"})
        self.assertTrue(a.startswith('<165>1 '+dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT')))
        self.assertIn("Z host app - - - src=",a)
        self.assertNotEqual(s,a)

    def test_cef_leef_kv_safe(self):
        samples=[
          'CEF:0|Vendor|Product|1.0|100|Firewall|5|src=192.0.2.10 dst=203.0.113.10 suser=alice email=alice@example.test location=Seoul',
          'LEEF:2.0|Vendor|Product|1.0|100|0x09|src=192.0.2.10\tdst=198.51.100.1\tusername=alice',
        ]
        for s in samples:
            with self.subTest(s=s[:3]):
                a=update(s,{"format":"auto"})
                self.assertEqual(s.split("|",1)[0],a.split("|",1)[0])
                self.assertNotIn("alice@example.test",a)
                self.assertNotIn("username=alice",a)
                self.assertNotIn("suser=alice",a)
                # Compare the full lexical field value: a new .102 address
                # is not the original .10 address even though it has that prefix.
                self.assertIn("src=",a)
                source_address=a.split("src=",1)[1].split()[0]
                self.assertNotEqual(source_address,"192.0.2.10")

    def test_csv_lexical_quotes_and_current_time(self):
        s='"error, escalated",2020/10/17 11:12:13,192.0.2.10,alice,alice@example.test,"New York"'
        names=["message","timestamp","src_ip","username","email","location"]
        a=update(s,{"format":"csv","csv_columns":names,"csv_delimiter":","})
        values=list(csv.reader(io.StringIO(a),strict=True))[0]
        self.assertEqual(len(values),len(names))
        self.assertTrue(a.startswith('"error, escalated",'))
        self.assertEqual(values[1],dt.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
        self.assertNotEqual(values[2],"192.0.2.10")
        self.assertNotEqual(values[3],"alice")
        self.assertTrue(values[4].endswith("@example.test"))
        self.assertIn(values[5],CITIES)
        self.assertEqual(update('a,"not closed',{"format":"csv",
            "csv_columns":["first","second"],"csv_delimiter":","}),'a,"not closed')

    def test_ip_mutation_is_single_pass_and_cannot_revert_to_original(self):
        # Pin two successive random choices: one creates a new IP, but
        # the old second global replacement reverted it to the source IP.
        cases=[
            ('json','{"src_ip":"192.0.2.10"}',{'format':'json'}),
            ('kv','src_ip=192.0.2.10 action=allow',{'format':'kv'}),
            ('csv','192.0.2.10,allow',
             {'format':'csv','csv_columns':['src_ip','action'],'csv_delimiter':','}),
        ]
        for name,source,config in cases:
            with self.subTest(name=name):
                with mock.patch.object(runtime['secrets'],'choice',
                                       side_effect=['198.51.100.','192.0.2.']) as choice:
                    with mock.patch.object(runtime['secrets'],'randbelow',
                                           side_effect=[9,9]) as draw:
                        actual=update(source,config)
                if name=='json': value=json.loads(actual)['src_ip']
                elif name=='csv': value=next(csv.reader([actual]))[0]
                else: value=actual.split('src_ip=',1)[1].split(' ',1)[0]
                self.assertEqual(value,'198.51.100.10')
                self.assertNotEqual(value,'192.0.2.10')
                self.assertEqual(choice.call_count,1)
                self.assertEqual(draw.call_count,1)

    def test_epoch_json_numeric_type(self):
        s='{"eventtime":1600000000000,"time":1600000000,"action":"deny"}'
        a=json.loads(update(s,{"format":"json"}))
        self.assertIsInstance(a["eventtime"],int)
        self.assertIsInstance(a["time"],int)
        self.assertTrue(1000000000000<a["eventtime"]<9999999999999)
        self.assertLess(abs(a["time"]-int(dt.datetime.now().timestamp())),4)
        self.assertEqual(a["action"],"deny")

if __name__=="__main__":
    unittest.main()
