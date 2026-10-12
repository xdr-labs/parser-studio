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
