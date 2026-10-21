import assert from "node:assert/strict";
import test from "node:test";
import {compilePair,validateProject} from "../src/index.js";
import {sampleProject} from "./fixture.js";
import {proposeParserPort,validatePortOverride} from "../src/stellar-port-plan.js";

const inventory=()=>{
  return {
    cataloguePorts:[6800,6801,6803],
    tenantLegacyPorts:[6802],
    sensorParserPorts:[7000],
    localReservedPorts:[7001],
    adminReservedPorts:[],
    evidence:{
      catalogueComplete:true,tenantComplete:true,
      sensorBindingsComplete:true,reservationsComplete:true,
    },
  };
};

test("RFC5424 Syslog parser receiver port must be >=6800 before generating Ruby/CONF",()=>{
  const parser=sampleProject();
  parser.extraction={format:"syslog_rfc5424",syslogBodyFormat:"kv"};
  parser.receiver.port=6799;
  const bad=validateProject(parser);
  assert.equal(bad.ok,false);
  assert.ok(bad.issues.some(x=>
    x.path==="/receiver/port"&&
    ["syslog_port_minimum","schema"].includes(x.code)),JSON.stringify(bad));
  assert.throws(()=>compilePair(parser),/Invalid parser project/);
  parser.receiver.port=6800;
  assert.equal(validateProject(parser).ok,true);
  const exact=compilePair(parser).files.find(x=>x.name.endsWith(".conf"));
  assert.ok(exact);
  assert.match(exact.content,/^\s+port 6800$/m);
});

test("one selected UDP Syslog port is emitted once in the source and reused as sensor destination",()=>{
  const project=sampleProject();
  project.receiver.port=6800;
  project.receiver.protocols=["udp"];
  project.extraction={format:"syslog_rfc5424",syslogBodyFormat:"kv"};
  const result=compilePair(project);
  const conf=result.files.find(file=>file.name.endsWith(".conf"))!.content;
  assert.equal((conf.match(/<source>/g)||[]).length,1);
  assert.equal((conf.match(/\bport 6800\b/g)||[]).length,1);
  assert.match(conf,/@type udp/);
  assert.doesNotMatch(conf,/@type tcp/);
  assert.equal(proposeParserPort(inventory(),{
    parserFormat:"syslog_rfc5424",requestedPort:6810,
  }).sensorIngestPort,6810);
});

test("non-Syslog formats are unaffected by the Syslog-only listener minimum",()=>{
  const parser=sampleProject();
  parser.receiver.port=6799;
  assert.equal(validateProject(parser).ok,true);
  assert.match(compilePair(parser).files[0]!.content,/^\s+port 6799$/m);
});

test("Syslog listener port planner proposes 6800+ and skips all known occupied ports",()=>{
  const proposal=proposeParserPort(inventory(),{parserFormat:"syslog_rfc5424"});
  assert.equal(proposal.recommendedPort,6804);
  assert.equal(proposal.deployableNow,false);
  assert.equal(proposal.needsFinalRecheck,true);
  assert.equal(proposal.verifiedIngestPort,false);
  assert.equal(proposal.sensorIngestPort,proposal.recommendedPort);
});

test("Syslog user overrides and lower custom ranges cannot break 6800 minimum",()=>{
  assert.throws(()=>validatePortOverride(6799,inventory(),"syslog_rfc5424"),/PORT_SYSLOG_MINIMUM/);
  assert.throws(()=>proposeParserPort(inventory(),{
    parserFormat:"syslog_rfc5424",requestedPort:6799}),/PORT_SYSLOG_MINIMUM/);
  assert.throws(()=>proposeParserPort(inventory(),{
    parserFormat:"syslog_rfc5424",rangeStart:6799,rangeEnd:6810}),/PORT_SYSLOG_MINIMUM/);
  assert.throws(()=>proposeParserPort(inventory(),{
    parserFormat:"syslog_rfc5424",requestedPort:6800}),/PORT_ALREADY_OCCUPIED/);
  assert.equal(proposeParserPort(inventory(),{
    parserFormat:"syslog_rfc5424",requestedPort:6810}).recommendedPort,6810);
});

test("RFC3164 listener and sensor destination always share a permitted Syslog port",()=>{
  const evidence=inventory();
  assert.throws(()=>proposeParserPort(evidence,{parserFormat:"syslog_rfc3164",
    requestedPort:6799}),/PORT_SYSLOG_MINIMUM/);
  const suggestion=proposeParserPort(evidence,{parserFormat:"syslog_rfc3164"});
  assert.ok(suggestion.recommendedPort>=6800);
  assert.equal(suggestion.sensorIngestPort,suggestion.recommendedPort);
  assert.equal(suggestion.deployableNow,false);
});

// The compiler uses the first-use choice verbatim; it cannot certify target occupancy.
test("new 6801 default and user override reach generated DRAFT CONF exactly",()=>{
  for(const chosen of [6801,6905]){
    const project=sampleProject();
    project.receiver.port=chosen;
    project.receiver.protocols=["udp","tcp"];
    const conf=compilePair(project).files.find(file=>file.name.endsWith(".conf"))!.content;
    const ports=[...conf.matchAll(/^\s+port (\d+)\s*$/gm)].map(match=>Number(match[1]));
    assert.ok(ports.length>0);
    assert.deepEqual([...new Set(ports)],[chosen]);
  }
});
