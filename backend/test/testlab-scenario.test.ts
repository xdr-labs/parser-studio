import assert from "node:assert/strict";
import test from "node:test";
import {
  validateReplayScenario,selectScenarioPreview,
} from "../src/testlab-scenario.js";

const runId="test_run_0123456789abcdef0123456789abcdef";
const now=Date.parse("2026-10-12T01:02:03Z");
const events=[
  {id:"firewall",offsetMs:0,sample:{
    format:"kv" as const,source:"src_ip=192.0.2.1 action=deny run_id=old",
    seed:1,sequence:0,variableFields:[{path:"src_ip",kind:"ipv4" as const}],
    runMarkerField:"run_id",
  }},
  {id:"proxy",offsetMs:400,sample:{
    format:"cef" as const,
    source:"CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.2 act=deny run_id=old",
    seed:2,sequence:0,variableFields:[{path:"src",kind:"ipv4" as const}],
    runMarkerField:"run_id",
  }},
  {id:"syslog",offsetMs:900,sample:{
    format:"syslog_rfc5424" as const,syslogBodyFormat:"kv" as const,
    source:"<165>1 2025-01-01T01:02:03Z edge fw 1 ID - src_ip=192.0.2.3 action=deny run_id=old",
    seed:3,sequence:0,variableFields:[{path:"body.src_ip",kind:"ipv4" as const}],
    runMarkerField:"body.run_id",
  }},
];

test("recorded-gap scenario cycles format families with bounded source gap and refreshed current times",()=>{
  const scenario={scenarioId:"synthetic-transaction",
    mode:"original-gaps" as const,cycleMs:1600,events};
  const inspected=validateReplayScenario(scenario,5);
  assert.equal(inspected.sampleFamilyCount,3);
  assert.equal(inspected.replayMode,"original-gaps");
  assert.equal(inspected.safeToSendToSensor,false);
  const first=selectScenarioPreview(scenario,0,now,runId,5);
  const second=selectScenarioPreview(scenario,1,now,runId,5);
  const third=selectScenarioPreview(scenario,2,now,runId,5);
  const fourth=selectScenarioPreview(scenario,3,now,runId,5);
  assert.deepEqual([first.nextDelayMs,second.nextDelayMs,third.nextDelayMs,fourth.nextDelayMs],
    [400,500,700,400]);
  assert.deepEqual([first.sampleId,second.sampleId,third.sampleId,fourth.sampleId],
    ["firewall","proxy","syslog","firewall"]);
  for(const item of [first,second,third,fourth]){
    assert.equal(item.preview.runtimeParsingVerified,false);
    assert.ok(item.preview.syntheticEvent.includes("run_id="+runId));
  }
  assert.match(third.preview.syntheticEvent,/^<165>1 2026-10-12T01:02:03Z /);
  assert.equal(selectScenarioPreview(scenario,0,now,runId,5).preview.syntheticEvent,
    first.preview.syntheticEvent);
});

test("constant-rate scenario alternates event family without unbounded delays",()=>{
  const scenario={scenarioId:"synthetic-rotation",
    mode:"constant-rate" as const,
    events:events.map(({id,sample})=>({id,sample}))};
  const result=validateReplayScenario(scenario,5);
  assert.equal(result.sampleFamilyCount,3);
  assert.equal(result.replayMode,"constant-rate");
  const picks=Array.from({length:6},(_,i)=>
    selectScenarioPreview(scenario,i,now,runId,5));
  assert.deepEqual(picks.map(x=>x.sampleId),
    ["firewall","proxy","syslog","firewall","proxy","syslog"]);
  assert.ok(picks.every(x=>x.nextDelayMs===200));
});

test("malformed scenario and high-frequency original-gap profiles fail closed",()=>{
  const base={scenarioId:"synthetic-transaction",
    mode:"original-gaps" as const,cycleMs:1600,events};
  const attacks=[
    {...base,events:[events[0]!,events[0]!] },
    {...base,events:events.map(x=>({...x,offsetMs:0}))},
    {...base,cycleMs:901},
    {...base,events:events.map((x,i)=>({...x,offsetMs:i*100}))},
    {...base,events:[{...events[0]!,sample:{...events[0]!.sample,runMarkerField:"unknown"}}]},
    {...base,scenarioId:"../../../secrets"},
    {...base,mode:"unknown"},
    {...base,events:Array.from({length:17},(_,i)=>({...events[0]!,id:"e"+i}))},
  ];
  for(const bad of attacks){
    assert.throws(()=>validateReplayScenario(bad as any,5),/TESTLAB_SCENARIO_/);
  }
  const tooFast={...base,cycleMs:4000,events};
  assert.throws(()=>validateReplayScenario(tooFast,1),/TESTLAB_SCENARIO_RATE_CONFLICT/);
});
