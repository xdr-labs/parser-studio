import assert from "node:assert/strict";
import test from "node:test";
import {createSyntheticPreview} from "../src/testlab-synthetic.js";

const now=Date.parse("2026-10-12T01:02:03.456Z");

test("JSON sample generates current ISO timestamp and deterministic safe synthetic IP/user/URL fields",()=>{
  const sample=JSON.stringify({
    event:{time:"2026-01-01T09:15:00Z"},
    source:{ip:"192.0.2.3"},destination:{ip:"198.51.100.7"},
    user:{name:"synthetic-old"},request:{url:"https://example.invalid/old"},
    action:"deny",test:{run_id:"synthetic-old-run"},
  });
  const options={format:"json" as const,source:sample,seed:42,sequence:4,
    timestampField:"event.time",
    variableFields:[
      {path:"source.ip",kind:"ipv4" as const},
      {path:"destination.ip",kind:"ipv4" as const},
      {path:"user.name",kind:"username" as const},
      {path:"request.url",kind:"url" as const},
    ],runMarkerField:"test.run_id",runId:"test-run-123456",
  };
  const result=createSyntheticPreview(options,now);
  assert.equal(result.generatedAt,"2026-10-12T01:02:03.456Z");
  assert.equal(result.safeToSendToSensor,false);
  assert.equal(result.runtimeParsingVerified,false);
  assert.equal(result.targetSensorVerified,false);
  const parsed=JSON.parse(result.syntheticEvent);
  assert.equal(parsed.event.time,"2026-10-12T01:02:03Z");
  assert.equal(parsed.action,"deny","unchanged classification field");
  assert.equal(parsed.test.run_id,"test-run-123456");
  assert.match(parsed.source.ip,/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/);
  assert.match(parsed.destination.ip,/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/);
  assert.match(parsed.user.name,/^synthetic_user_/);
  assert.match(parsed.request.url,/^https:\/\/synthetic\.invalid\//);
  assert.equal(createSyntheticPreview(options,now).syntheticEvent,result.syntheticEvent);
  assert.notEqual(createSyntheticPreview({...options,sequence:5},now).syntheticEvent,result.syntheticEvent);
  assert.equal(JSON.parse(sample).user.name,"synthetic-old","input never mutated");
});

test("RFC3339 offset and milliseconds are preserved when advancing source timestamps",()=>{
  const r=createSyntheticPreview({
    format:"json",source:JSON.stringify({time:"2026-01-01T00:00:00.123+09:00",action:"deny"}),
    seed:7,sequence:0,timestampField:"time",variableFields:[],
  },now);
  assert.equal(JSON.parse(r.syntheticEvent).time,"2026-10-12T10:02:03.456+09:00");
  assert.equal(JSON.parse(r.syntheticEvent).action,"deny");
});

test("strict unquoted KV subset remains parseable with timestamp, user and src IP changes",()=>{
  const r=createSyntheticPreview({
    format:"kv",source:"event_time=2026-01-01T01:02:03Z src_ip=192.0.2.12 user=synthetic-old action=allow",
    seed:123,sequence:22,timestampField:"event_time",
    variableFields:[{path:"src_ip",kind:"ipv4"},{path:"user",kind:"username"}],
  },now);
  assert.match(r.syntheticEvent,/^event_time=2026-10-12T01:02:03Z src_ip=/);
  assert.match(r.syntheticEvent,/user=synthetic_user_/);
  assert.match(r.syntheticEvent,/action=allow$/);
  assert.equal(r.safeToSendToSensor,false);
});

test("unsupported formats/quotes/paths/bounds fail closed without echoing private content",()=>{
  const sample=JSON.stringify({user:{name:"SECRET_NEVER_ECHO"},event:{time:"bad-date"}});
  const valid={format:"json" as const,source:sample,seed:1,sequence:0,
    variableFields:[{path:"user.name",kind:"username" as const}]};
  for(const broken of [
    {...valid,format:"cef"},
    {...valid,timestampField:"event.time"},
    {...valid,variableFields:[{path:"user.unknown",kind:"username" as const}]},
    {...valid,variableFields:[{path:"__proto__.danger",kind:"username" as const}]},
    {...valid,sequence:-1},
    {...valid,source:"x".repeat(20000)},
    {...valid,runMarkerField:"unknown",runId:"test-run-123456"},
  ]){
    let message="";
    try{createSyntheticPreview(broken as any,now);}catch(error){
      message=String((error as Error).message);
    }
    assert.match(message,/^TESTLAB_/,JSON.stringify(broken).slice(0,20));
    assert.equal(message.includes("SECRET_NEVER_ECHO"),false);
  }
  assert.throws(()=>createSyntheticPreview({
    format:"kv",source:"src_ip=\"quoted private secret\" action=deny",
    seed:12,sequence:0,variableFields:[{path:"src_ip",kind:"ipv4"}],
  },now),/TESTLAB_KV_UNSUPPORTED/);
});

test("CSV synthetic preview updates only chosen IP/user/timestamp while preserving column order and quoting",()=>{
  const preview=createSyntheticPreview({
    format:"csv",
    source:'192.0.2.4,443,"deny",2026-01-01T01:02:03Z,synthetic-old,test-run-old',
    csvColumns:["src_ip","dst_port","action","event_time","username","run_id"],
    csvDelimiter:",",
    seed:55,sequence:3,timestampField:"event_time",
    variableFields:[{path:"src_ip",kind:"ipv4"},{path:"username",kind:"username"}],
    runMarkerField:"run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  },now);
  assert.equal(preview.format,"csv");
  assert.match(preview.syntheticEvent,/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+,443,deny,2026-10-12T01:02:03Z,synthetic_user_/);
  assert.ok(preview.syntheticEvent.endsWith(",test_run_0123456789abcdef0123456789abcdef"));
  assert.equal(preview.safeToSendToSensor,false);
  assert.equal(preview.runtimeParsingVerified,false);
});

test("CSV quoting and alternative delimiter preserve unchanged field values",()=>{
  const preview=createSyntheticPreview({
    format:"csv",
    source:'203.0.113.1;"Allowed; Reviewed";"say ""hello""";2026-01-01T01:02:03Z',
    csvColumns:["src_ip","classification","message","timestamp"],
    csvDelimiter:";",
    seed:9,sequence:0,timestampField:"timestamp",
    variableFields:[{path:"src_ip",kind:"ipv4"}],
  },now);
  assert.match(preview.syntheticEvent,/^((192\.0\.2|198\.51\.100|203\.0\.113)\.\d+);/);
  assert.ok(preview.syntheticEvent.includes(';"Allowed; Reviewed";"say ""hello""";'));
  assert.ok(preview.syntheticEvent.endsWith("2026-10-12T01:02:03Z"));
});

test("malformed CSV, duplicate schema, unsupported delimiter and multiline fail without echoing source",()=>{
  const base={
    format:"csv",source:"192.0.2.1,443,PRIVATE_SECRET_ROW",
    csvColumns:["src_ip","dst_port","action"],
    seed:4,sequence:1,variableFields:[{path:"src_ip",kind:"ipv4"}],
  };
  for(const broken of [
    {...base,source:"192.0.2.1,443"},
    {...base,source:'"192.0.2.1,443,PRIVATE_SECRET_ROW'},
    {...base,source:'192.0.2.1,443,"action"garbage'},
    {...base,source:"192.0.2.1,443,PRIVATE_SECRET_ROW\n"},
    {...base,csvColumns:["src_ip","dst_port","src_ip"]},
    {...base,csvColumns:["src_ip","__proto__","action"]},
    {...base,csvDelimiter:"|"},
    {...base,variableFields:[{path:"not_a_column",kind:"ipv4"}]},
  ]){
    let text="";
    try{createSyntheticPreview(broken as any,now);}
    catch(error){text=(error as Error).message;}
    assert.match(text,/^TESTLAB_CSV_|^TESTLAB_FIELD_MISSING/,JSON.stringify(broken).slice(0,70));
    assert.ok(!text.includes("PRIVATE_SECRET_ROW"));
  }
});

test("CEF 0 synthetic header remains stable and selected KV body fields rotate safely",()=>{
  const source="CEF:0|Synthetic|FW|1|42|Denied\\|Policy|8|src=192.0.2.10 dpt=443 act=deny rt=2025-01-01T01:02:03Z user=old run_id=old";
  const value=createSyntheticPreview({
    format:"cef",source,seed:10,sequence:4,timestampField:"rt",
    variableFields:[{path:"src",kind:"ipv4"},{path:"user",kind:"username"}],
    runMarkerField:"run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  },now);
  assert.equal(value.format,"cef");
  assert.ok(value.syntheticEvent.startsWith("CEF:0|Synthetic|FW|1|42|Denied\\|Policy|8|"));
  assert.match(value.syntheticEvent,/src=(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+ /);
  assert.ok(value.syntheticEvent.includes(" dpt=443 act=deny rt=2026-10-12T01:02:03Z "));
  assert.ok(value.syntheticEvent.includes("user=synthetic_user_"));
  assert.ok(value.syntheticEvent.endsWith("run_id=test_run_0123456789abcdef0123456789abcdef"));
  assert.equal(value.runtimeParsingVerified,false);
  assert.equal(createSyntheticPreview({...{
    format:"cef" as const,source,seed:10,sequence:4,timestampField:"rt",
    variableFields:[{path:"src",kind:"ipv4" as const},{path:"user",kind:"username" as const}],
    runMarkerField:"run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  }},now).syntheticEvent,value.syntheticEvent);
});

test("LEEF 2.0 hexadecimal field separator preserves header, classification and timestamps",()=>{
  const source="LEEF:2.0|Synthetic|FW|1|501|0x5E|src=203.0.113.2^dstPort=443^act=allow^rt=2025-01-01T01:02:03Z^user=old^run_id=old";
  const value=createSyntheticPreview({
    format:"leef",source,seed:32,sequence:2,timestampField:"rt",
    variableFields:[{path:"src",kind:"ipv4"},{path:"user",kind:"username"}],
    runMarkerField:"run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  },now);
  assert.ok(value.syntheticEvent.startsWith("LEEF:2.0|Synthetic|FW|1|501|0x5E|"));
  assert.ok(value.syntheticEvent.includes("^dstPort=443^act=allow^rt=2026-10-12T01:02:03Z^"));
  assert.ok(value.syntheticEvent.includes("^user=synthetic_user_"));
  assert.ok(value.syntheticEvent.endsWith("^run_id=test_run_0123456789abcdef0123456789abcdef"));
  assert.equal(value.targetSensorVerified,false);
});

test("unsupported CEF/LEEF versions, delimiters and malformed extensions reject without echoing input",()=>{
  const cef="CEF:0|Synthetic|FW|1|42|Denied|8|src=192.0.2.1 act=deny PRIVATE_SECRET=1";
  const leef="LEEF:2.0|Synthetic|FW|1|501|^|src=203.0.113.8^act=deny";
  for(const change of [
    {format:"cef",source:cef.replace("CEF:0","CEF:9")},
    {format:"cef",source:cef.replace("act=deny","stray-token")},
    {format:"cef",source:"CEF:0|Synthetic|FW|1|42|Denied\\",variableFields:[]},
    {format:"leef",source:leef.replace("|^|","|0x00|")},
    {format:"leef",source:leef.replace("^act=deny","^^act=deny")},
    {format:"leef",source:leef.replace("LEEF:2.0","LEEF:3.0")},
    {format:"leef",source:leef.replace("^act=deny","^run_id=duplicate^run_id=duplicate")},
  ]){
    let message="";
    try{
      createSyntheticPreview({format:change.format as any,source:change.source,
        seed:5,sequence:0,variableFields:change.variableFields??[{path:"src",kind:"ipv4"}]},
        now);
    }catch(error){message=(error as Error).message;}
    assert.match(message,/^TESTLAB_(CEF|LEEF)_/);
    assert.equal(message.includes("PRIVATE_SECRET"),false);
  }
});

test("LEEF 1.0 TAB and LEEF 2.0 hexadecimal pipe delimiter replay safely",()=>{
  const older=createSyntheticPreview({
    format:"leef",
    source:"LEEF:1.0|Synthetic|FW|1|500|src=192.0.2.3\tdstPort=443\tact=deny\trun_id=old",
    seed:100,sequence:5,
    variableFields:[{path:"src",kind:"ipv4"}],
    runMarkerField:"run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  },now);
  assert.match(older.syntheticEvent,/^LEEF:1\.0\|Synthetic\|FW\|1\|500\|src=/);
  assert.ok(older.syntheticEvent.includes("\tdstPort=443\tact=deny\trun_id=test_run_"));
  const pipe=createSyntheticPreview({
    format:"leef",
    source:"LEEF:2.0|Synthetic|FW|1|501|0x7C|src=192.0.2.3|dstPort=443|act=deny|run_id=old",
    seed:100,sequence:5,
    variableFields:[{path:"src",kind:"ipv4"}],
    runMarkerField:"run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  },now);
  assert.ok(pipe.syntheticEvent.startsWith("LEEF:2.0|Synthetic|FW|1|501|0x7C|"));
  assert.ok(pipe.syntheticEvent.includes("|dstPort=443|act=deny|run_id=test_run_"));
  assert.equal(pipe.runtimeParsingVerified,false);
});

test("RFC5424 KV synthetic preview updates header clock and nested body fields without rewriting PRI/identity",()=>{
  const sample="<165>1 2025-01-01T01:02:03Z edge-fw firewall 123 ID42 - src_ip=192.0.2.3 action=deny user=old run_id=old";
  const input={
    format:"syslog_rfc5424" as const,syslogBodyFormat:"kv" as const,
    source:sample,seed:75,sequence:3,
    timestampField:"syslog_timestamp",
    variableFields:[{path:"body.src_ip",kind:"ipv4" as const},
      {path:"body.user",kind:"username" as const}],
    runMarkerField:"body.run_id",runId:"test_run_0123456789abcdef0123456789abcdef",
  };
  const result=createSyntheticPreview(input,now);
  assert.equal(result.format,"syslog_rfc5424");
  assert.match(result.syntheticEvent,
    /^<165>1 2026-10-12T01:02:03Z edge-fw firewall 123 ID42 - src_ip=/);
  assert.ok(result.syntheticEvent.includes(" action=deny user=synthetic_user_"));
  assert.ok(result.syntheticEvent.endsWith("run_id=test_run_0123456789abcdef0123456789abcdef"));
  assert.ok(result.changedPaths.includes("syslog_timestamp"));
  assert.ok(result.changedPaths.includes("body.src_ip"));
  assert.equal(result.safeToSendToSensor,false);
  assert.equal(createSyntheticPreview(input,now).syntheticEvent,result.syntheticEvent);
  assert.equal(sample.includes("2025-01-01"),true);
});

test("RFC5424 offset and selected nested body timestamp advance using current clock",()=>{
  const result=createSyntheticPreview({
    format:"syslog_rfc5424",syslogBodyFormat:"kv",
    source:"<165>1 2025-01-01T01:02:03+09:00 edge fw 1 ID - src_ip=192.0.2.3 action=allow event_time=2025-01-01T02:03:04Z",
    seed:19,sequence:1,timestampField:"body.event_time",
    variableFields:[{path:"body.src_ip",kind:"ipv4"}],
  },now);
  assert.match(result.syntheticEvent,/^<165>1 2026-10-12T10:02:03\+09:00 edge fw 1 ID - src_ip=/);
  assert.ok(result.syntheticEvent.endsWith("action=allow event_time=2026-10-12T01:02:03Z"));
});

test("RFC5424 synthetic replay fails closed on unknown version, invalid timestamp, SD extensions and body format",()=>{
  const source="<165>1 2025-01-01T01:02:03Z edge fw 1 ID - src_ip=192.0.2.7 action=deny PRIVATE_SOURCE=never-echo";
  const input={
    format:"syslog_rfc5424" as const,syslogBodyFormat:"kv" as const,
    source,seed:18,sequence:0,
    variableFields:[{path:"body.src_ip",kind:"ipv4" as const}],
  };
  for(const bad of [
    {...input,source:source.replace(">1 ",">2 ")},
    {...input,source:source.replace("2025-01-01T01:02:03Z","not-timestamp")},
    {...input,source:source.replace(" - src_ip"," [origin@32473] src_ip")},
    {...input,source:source.replace("edge","\uD14C\uC2A4\uD2B8")},
    {...input,syslogBodyFormat:"cef"},
    {...input,source:source.replace("action=deny","action=\"quoted value\"")},
  ]){
    let message="";
    try{createSyntheticPreview(bad as any,now);}catch(error){message=(error as Error).message;}
    assert.match(message,/^TESTLAB_SYSLOG_/);
    assert.equal(message.includes("PRIVATE_SOURCE"),false);
  }
});
