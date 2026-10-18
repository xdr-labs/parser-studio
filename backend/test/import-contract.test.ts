import assert from "node:assert/strict";
import test from "node:test";
import { compilePair, inspectPair } from "../src/index.js";
import { sampleProject } from "./fixture.js";

test("generated pair round trips exactly to an editable project", () => {
  const p = sampleProject();
  const {files} = compilePair(p);
  const checked = inspectPair({
    name: "customized_sample_firewall",
    confContent: files[0]!.content,
    fragmentContent: files[1]!.content,
  });
  assert.equal(checked.format, "host-customized-pair");
  assert.equal(checked.roundTripVerified, true);
  assert.equal(checked.importStatus, "EDITABLE_EXACT");
  assert.deepEqual(checked.portableProject, p);
  assert.deepEqual(checked.receiver.protocols, ["udp", "tcp"]);
  assert.deepEqual(checked.receiver.ports, [7123]);
  assert.equal(checked.originalHashes.conf, files[0]!.sha256);
  assert.equal(checked.originalHashes.fragment, files[1]!.sha256);
});

test("tampered generated config is not labeled editable or compatible", () => {
  const pair = compilePair(sampleProject());
  const parsed = inspectPair({
    name: "customized_sample_firewall",
    confContent: pair.files[0]!.content.replace("port 7123", "port 7211"),
    fragmentContent: pair.files[1]!.content,
  });
  assert.equal(parsed.roundTripVerified, false);
  assert.equal(parsed.portableProject, null);
  assert.ok(parsed.warnings.some(w=>w.includes("not byte-for-byte")));
});

test("opaque legacy Ruby with known markers is preserved conceptually as NOT editable", () => {
  const legacy = inspectPair({
    name: "customized_example",
    confContent: "<source>\n  @type udp\n  port 7500\n  tag customized_example\n  <parse>\n   @type customized_example\n  </parse>\n</source>",
    fragmentContent: "# STELLAR_INIT_BEGIN\ndef initialize; end\n# STELLAR_INIT_END\n# STELLAR_PARSE_BEGIN\ndef parse(text); yield nil, {}; end\n# STELLAR_PARSE_END",
  });
  assert.equal(legacy.importStatus, "OPAQUE_READ_ONLY");
  assert.equal(legacy.roundTripVerified, false);
  assert.equal(legacy.portableProject, null);
  assert.equal(legacy.receiver.ports[0], 7500);
  assert.equal(legacy.fragment.markersComplete, true);
  assert.ok(legacy.warnings.length);
});

test("mismatched pair name, malformed input and large file must be rejected", () => {
  assert.throws(()=>inspectPair({name:"../escape",confContent:"a",fragmentContent:"b"}),/Invalid parser pair name/);
  assert.throws(()=>inspectPair({name:"customized_big",confContent:"x".repeat(2100000),fragmentContent:"a"}),/Import size limit/);
  const invalid = inspectPair({
    name:"customized_example",
    confContent:"<source>\n@type udp\nport 7500\ntag customized_else\n</source>",
    fragmentContent:"# STELLAR_INIT_BEGIN\n# STELLAR_INIT_END",
  });
  assert.equal(invalid.roundTripVerified, false);
  assert.ok(invalid.warnings.some(w=>w.includes("inconsistent")));
});

test("analyzer must never return raw imported Ruby or CONF contents", () => {
  const secret="test-sensitive-string-not-in-output";
  const result=inspectPair({
    name:"customized_demo",
    confContent:"<source>\n @type tcp\n port 7020\n tag customized_demo\n</source>",
    fragmentContent:"# STELLAR_INIT_BEGIN\n# "+secret+"\n# STELLAR_INIT_END\n# STELLAR_PARSE_BEGIN\ndef parse(text); end\n# STELLAR_PARSE_END",
  });
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test("structured inspection diagnostic codes remain safe on tampered or legacy pairs", () => {
  const pair=compilePair(sampleProject());
  const modified=inspectPair({
    name:"customized_sample_firewall",
    confContent:pair.files[0]!.content.replace("port 7123","port 7200"),
    fragmentContent:pair.files[1]!.content,
  });
  assert.equal(modified.importStatus,"OPAQUE_READ_ONLY");
  assert.ok(modified.diagnostics.some(d=>d.code==="PAIR_NOT_REPRODUCIBLE"));
  assert.equal(modified.portableProject,null);
  assert.ok(modified.diagnostics.every(d=>typeof d.message==="string" && typeof d.code==="string"));

  const unsafe="UNIQUE_PRIVATE_RUBY_DO_NOT_EXPOSE";
  const opaque=inspectPair({
    name:"customized_example",
    confContent:"# <source>\n<source>\n # @type udp\n @type tcp\n # port 3333\n port 7201\n # tag customized_else\n tag customized_example\n <parse>\n @type customized_example\n </parse>\n</source>",
    fragmentContent:"# "+unsafe+"\n# STELLAR_INIT_BEGIN\n# STELLAR_INIT_END",
  });
  assert.equal(opaque.receiver.sourceCount,1);
  assert.deepEqual(opaque.receiver.protocols,["tcp"]);
  assert.deepEqual(opaque.receiver.ports,[7201]);
  assert.ok(opaque.diagnostics.some(d=>d.code==="RUBY_MARKERS_INCOMPLETE"));
  assert.ok(opaque.diagnostics.some(d=>d.code==="RUBY_PARSE_ENTRY_MISSING"));
  assert.equal(JSON.stringify(opaque).includes(unsafe),false);
});

test("reject invalid input with stable codes; structurally invalid receivers stay opaque", () => {
  assert.throws(()=>inspectPair({name:"../secret",confContent:"",fragmentContent:""}), (error:any)=>error.code==="PAIR_NAME_INVALID");
  assert.throws(()=>inspectPair(null as any), (error:any)=>error.code==="PAIR_NAME_INVALID");
  assert.throws(()=>inspectPair({name:"customized_valid",confContent:42 as any,fragmentContent:""}), (error:any)=>error.code==="PAIR_CONTENT_INVALID");
  assert.throws(()=>inspectPair({name:"customized_valid",confContent:"☃".repeat(700000),fragmentContent:""}), (error:any)=>error.code==="PAIR_SIZE_EXCEEDED");
  const legacy=inspectPair({
    name:"customized_legacy",
    confContent:"<source>\n @type exec\n port 99999\n <parse>\n  @type customized_else\n </parse>\n</source>",
    fragmentContent:"# private legacy source",
  });
  assert.deepEqual(legacy.receiver.protocols,[]);
  assert.deepEqual(legacy.receiver.ports,[]);
  for (const code of ["CONF_UNSUPPORTED_PROTOCOL","CONF_INVALID_PORT","CONF_SOURCE_MISMATCH","RUBY_MARKERS_INCOMPLETE","PAIR_NOT_REPRODUCIBLE"]) {
    assert.ok(legacy.diagnostics.some(d=>d.code===code),code);
  }
  assert.equal(legacy.importStatus,"OPAQUE_READ_ONLY");
});

test("sanitized legacy reference-layout HTTP and split-port receivers stay read-only", () => {
  // Synthesized structures only: no vendor config bodies or actual port values.
  const httpConf = [
    "<source>", "  @type http", "  port 8101",
    "  tag customized_reference_http",
    "  <parse>", "    @type customized_reference_http", "  </parse>",
    "</source>",
  ].join("\r\n");
  const source = "# STELLAR_INIT_BEGIN\n# STELLAR_INIT_END\n# STELLAR_PARSE_BEGIN\ndef parse(text)\n yield nil, {}\nend\n# STELLAR_PARSE_END";
  const http = inspectPair({
    name: "customized_reference_http", confContent: httpConf, fragmentContent: source,
  });
  assert.equal(http.importStatus, "OPAQUE_READ_ONLY");
  assert.deepEqual(http.receiver.protocols, ["http"]);
  assert.deepEqual(http.receiver.ports, [8101]);
  assert.equal(http.receiver.sourceCount, 1);
  assert.ok(http.diagnostics.some(x => x.code === "CONF_RECEIVER_NOT_EDITABLE"));

  const splitPort = inspectPair({
    name: "customized_reference_split",
    confContent: [
      "<source>\n @type udp\n port 8102\n tag customized_reference_split",
      " <parse>\n  @type customized_reference_split\n </parse>\n</source>",
      "<source>\n @type tcp\n port 8103",
      " @include /etc/td-agent/transport_settings.conf",
      " tag customized_reference_split\n <parse>",
      "  @type customized_reference_split\n </parse>\n</source>",
    ].join("\n"),
    fragmentContent: source,
  });
  assert.equal(splitPort.importStatus, "OPAQUE_READ_ONLY");
  assert.deepEqual(splitPort.receiver.protocols, ["udp", "tcp"]);
  assert.deepEqual(splitPort.receiver.ports, [8102, 8103]);
  assert.equal(splitPort.receiver.sourceCount, 2);
  assert.ok(splitPort.diagnostics.some(x => x.code === "CONF_MULTI_PORT_LAYOUT"));
});
