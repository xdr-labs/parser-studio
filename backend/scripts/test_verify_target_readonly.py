"""Entirely offline contract/security verification. All tokens are FAKE."""
from contextlib import redirect_stdout
from io import StringIO
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib import error
from unittest.mock import patch

SOURCE=Path(__file__).with_name("verify-target-readonly.py")
spec=importlib.util.spec_from_file_location("parser_studio_readonly_probe",SOURCE)
assert spec and spec.loader
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
TEST_KEY="synthetic_key_NEVER_SAVE_THIS"
TEST_JWT="synthetic_jwt_NEVER_PRINT_THIS"
P={
  "host":"https://poc-apac.stellarcyber.cloud",
  "tenant":"synthetic_tenant",
  "key":TEST_KEY,
}


class FakeResponse:
    def __init__(self,status:int,data:object):
        self.status=status
        self.raw=json.dumps(data).encode("utf-8")
    def __enter__(self):
        return self
    def __exit__(self,*args):
        return False
    def read(self,max_bytes:int):
        return self.raw[:max_bytes]


class FakeOpener:
    def __init__(self):
        self.calls=[]
    def open(self,req,timeout):
        self.calls.append({
          "method":req.get_method(),"url":req.full_url,
          "auth":req.get_header("Authorization"),
          "timeout":timeout,
        })
        if req.full_url.endswith("/access_token"):
            return FakeResponse(200,{"access_token":TEST_JWT})
        if "/parsers?" in req.full_url:
            return FakeResponse(200,{"data":[
                {"parser_name":"secret_existing_customer_parser","port":6001},
                {"parser_name":"secret_other_customer_parser","port":6001},
                {"parser_name":"secret_third","port":6002},
            ]})
        return FakeResponse(200,{"data":[
            {"parser_name":"secret_existing_customer_parser","port":7022},
            {"parser_name":"secret_second","port":7023},
        ]})


class VerifyContractTests(unittest.TestCase):
    def test_exact_fixed_api_contract_auth_then_two_gets(self):
        calls=[]
        def fake(method,route,auth,*,tenant):
            calls.append((method,route,auth,tenant))
            if method=="POST":
                return 200,{"access_token":TEST_JWT}
            return 200,{"data":[
              {"parser_name":"CUSTOMER_SECRET_NEVER_SHOW","port":6800},
              {"parser_name":"CUSTOMER_SECRET_NEVER_SHOW2","port":6800},
            ]}
        out=probe.verify(P,send=fake)
        self.assertTrue(out["auth"]["jwtExchanged"])
        self.assertEqual(out["auth"]["httpStatus"],200)
        self.assertEqual(len(out["reads"]),2)
        self.assertEqual(calls[0],("POST","/access_token",TEST_KEY,None))
        self.assertEqual([x[:2] for x in calls[1:]],[
          ("GET","/custom_log_parsers"),
          ("GET","/custom_log_parsers/parsers"),
        ])
        self.assertTrue(all(x[2]==TEST_JWT and x[3]==P["tenant"] for x in calls[1:]))
        self.assertEqual(out["operations"]["parserWrites"],0)
        self.assertEqual(out["operations"]["sensorSends"],0)
        self.assertEqual(out["reads"][0]["recordCount"],2)
        self.assertEqual(out["reads"][0]["distinctReportedPorts"],1)
        self.assertNotIn(TEST_KEY,json.dumps(out))
        self.assertNotIn(TEST_JWT,json.dumps(out))
        self.assertNotIn("CUSTOMER_SECRET_NEVER_SHOW",json.dumps(out))
        stdout=StringIO()
        with redirect_stdout(stdout):
            self.assertTrue(probe.print_result(out))
        output=stdout.getvalue()
        self.assertIn("POC_READ_ONLY_VALIDATION: PASS",output)
        self.assertNotIn("CUSTOMER_SECRET",output)

    def test_request_layer_allows_exact_three_approved_method_route_pairs(self):
        opener=FakeOpener()
        code,obj=probe.request_json("POST","/access_token",TEST_KEY,tenant=None,opener=opener)
        self.assertEqual(code,200)
        self.assertEqual(obj["access_token"],TEST_JWT)
        for route in probe.GET_ROUTES:
            code,reply=probe.request_json("GET",route,TEST_JWT,
                                          tenant="synthetic_tenant",opener=opener)
            self.assertEqual(code,200)
            self.assertIsInstance(reply["data"],list)
        self.assertEqual([x["method"] for x in opener.calls],["POST","GET","GET"])
        self.assertTrue(all(x["url"].startswith(probe.ALLOWED_POC_ORIGIN+probe.PREFIX)
                            for x in opener.calls))
        self.assertTrue(all(x["auth"].startswith("Bearer ") for x in opener.calls))
        self.assertTrue(all("cust_id=synthetic_tenant" in x["url"] for x in opener.calls[1:]))

    def test_no_parser_writes_activations_or_third_party_endpoints(self):
        opener=FakeOpener()
        for method,route,tenant in [
            ("POST","/custom_log_parsers",None),
            ("PUT","/custom_log_parsers",None),
            ("DELETE","/custom_log_parsers/foo",None),
            ("GET","/custom_log_parsers/foo","synthetic_tenant"),
            ("GET","/connect/api/data/session/_search","synthetic_tenant"),
            ("POST","/access_token","synthetic_tenant"),
            ("GET","/access_token",None),
            ("GET","/custom_log_parsers",None),
        ]:
            with self.subTest(method=method,route=route):
                with self.assertRaisesRegex(probe.ReadonlyProbeError,"METHOD_OR_ROUTE_UNAUTHORIZED"):
                    probe.request_json(method,route,"fake_token",tenant=tenant,opener=opener)
        self.assertEqual(opener.calls,[])

    def test_https_host_target_allowlist_fails_closed(self):
        for host in [
            "https://example.invalid","http://poc-apac.stellarcyber.cloud",
            "https://poc-apac.stellarcyber.cloud.evil.invalid",
            "https://poc-apac.stellarcyber.cloud/other",
            "https://user:token@poc-apac.stellarcyber.cloud",
        ]:
            with self.subTest(host=host):
                with self.assertRaisesRegex(probe.ReadonlyProbeError,"POC_ORIGIN_UNAUTHORIZED"):
                    probe.verify({**P,"host":host},send=lambda *_args,**_kw:(
                      self.fail("Network should never be reached")))
        self.assertEqual(probe.NoRedirect().redirect_request(
          None,None,302,"Moved",{}, "https://untrusted.invalid"),None)

    def test_jwt_failure_skips_all_gets(self):
        calls=[]
        def fail_auth(method,route,token,*,tenant):
            calls.append(method)
            return 401,{"error":"CUSTOMER_SECRET"}
        out=probe.verify(P,send=fail_auth)
        self.assertFalse(out["auth"]["jwtExchanged"])
        self.assertEqual(out["reads"],[])
        self.assertEqual(calls,["POST"])
        self.assertEqual(out["operations"]["get"],0)
        self.assertNotIn("CUSTOMER_SECRET",json.dumps(out))

    def test_read_403_or_invalid_vendor_shape_is_not_success(self):
        def read_denied(method,route,token,*,tenant):
            if method=="POST":
                return 200,{"access_token":TEST_JWT}
            return 403,{"error":"TENANT_SECRET_403_MESSAGE"}
        result=probe.verify(P,send=read_denied)
        self.assertTrue(result["auth"]["jwtExchanged"])
        self.assertEqual(result["operations"]["get"],2)
        self.assertTrue(all(x["httpStatus"]==403 and not x["shapeValid"] for x in result["reads"]))
        self.assertNotIn("TENANT_SECRET",json.dumps(result))
        output=StringIO()
        with redirect_stdout(output):
            self.assertFalse(probe.print_result(result))
        self.assertIn("NOT_VERIFIED",output.getvalue())
        def bad_shape(method,route,token,*,tenant):
            return (200,{"access_token":TEST_JWT}) if method=="POST" else (200,{"data":{"foo":1}})
        result=probe.verify(P,send=bad_shape)
        self.assertTrue(all(not x["shapeValid"] for x in result["reads"]))

    def test_real_private_profile_import_with_fake_home_and_no_network(self):
        with tempfile.TemporaryDirectory(prefix="parserstudio-readonly-") as home:
            directory=Path(home)/".parser-studio-secrets"
            directory.mkdir(mode=0o700)
            profile=directory/"connection.json"
            body={
                "schema":"parser-studio.target-connection.v0.1",
                "dp":{"url":P["host"],"tenant_id":P["tenant"],"api_key":TEST_KEY},
                "sensor":{"ip":"192.0.2.25","port":6800,"protocol":"udp"},
                "parser":{"preferred_listener_port":None,"port_verified":False},
                "deployment":{"automatic_apply_enabled":False},
            }
            profile.write_text(json.dumps(body),encoding="utf-8")
            os.chmod(profile,0o600)
            with patch.dict(os.environ,{"HOME":home}):
                loaded=probe.read_private_profile()
                self.assertEqual(loaded,P)
                self.assertNotIn("192.0.2.25",json.dumps(loaded))
                os.chmod(profile,0o644)
                with self.assertRaisesRegex(probe.ReadonlyProbeError,
                                            "PROFILE_UNAVAILABLE"):
                    probe.read_private_profile()

    def test_main_defaults_offline_without_loading_profile_or_network(self):
        with patch.object(probe,"read_private_profile",
                          side_effect=AssertionError("Do not read actual user profile by default")):
            out=StringIO()
            with redirect_stdout(out):
                rc=probe.main([])
            self.assertEqual(rc,0)
            self.assertIn("OFFLINE_ONLY",out.getvalue())
        cmd=subprocess.run([sys.executable,str(SOURCE)],capture_output=True,
                           text=True,timeout=10)
        self.assertEqual(cmd.returncode,0)
        self.assertIn("OFFLINE_ONLY",cmd.stdout)

    def test_profile_never_allows_raw_keys_in_output(self):
        for profile in [
            {**P,"tenant":"bad tenant"},
            {**P,"tenant":"../other"},
            {**P,"key":"fake\ninjection"},
            {**P,"key":""},
            {**P,"host":"localhost"},
        ]:
            with self.assertRaises(probe.ReadonlyProbeError):
                probe.validated_profile(profile)


if __name__=="__main__":
    unittest.main()
