import test from "node:test";
import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import {SyntheticSessionController} from "../src/testlab-session.js";
import {createApprovedSensorSink,type SensorTransportAudit} from "../src/testlab-transport.js";

const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
const fixture={
  format:"json" as const,
  source:JSON.stringify({
    time:"2025-01-01T12:00:00Z",source:{ip:"192.0.2.11"},
    action:"deny",test:{run_id:"synthetic_pending"},
  }),
  seed:1208,sequence:0,timestampField:"time",
  variableFields:[{path:"source.ip",kind:"ipv4" as const}],
  runMarkerField:"test.run_id",
};

test("Start generates multiple approved UDP loopback events and Stop halts without deleting any parser",async()=>{
  const socket=createSocket("udp4");
  await new Promise<void>(resolve=>socket.bind(0,"127.0.0.1",resolve));
  const target={ip:"127.0.0.1",port:(socket.address() as {port:number}).port,
    protocol:"udp" as const};
  const received:string[]=[];
  const events:SensorTransportAudit[]=[];
  socket.on("message",msg=>received.push(msg.toString("utf8")));
  const sink=createApprovedSensorSink({target,allowedTargets:[target],
    authorizeDelivery:async()=>true,
    auditDelivery:async item=>{events.push(item);},
  });
  const controller=new SyntheticSessionController({
    approveStart:async()=>true,deliver:sink,
  });
  try{
    const running=await controller.start({sample:fixture,
      approvalId:"owner-local-loopback",ratePerSecond:5,
      leaseMs:1400,maxEvents:10,
    },"test-local-actor");
    assert.equal(running.state,"RUNNING");
    await sleep(520);
    assert.ok(received.length>=2);
    assert.ok(received.every(raw=>JSON.parse(raw).test.run_id===running.runId));
    assert.ok(received.every(raw=>JSON.parse(raw).action==="deny"));
    assert.equal(received.some(raw=>raw.endsWith("\n")),false,
      "UDP preserves raw parser event bytes");
    const stopped=controller.stop(running.runId,"test-local-actor");
    assert.equal(stopped.parserLifecycleNotModified,true);
    assert.equal(stopped.sensorIngestVerified,false);
    const done=received.length;
    await sleep(340);
    assert.equal(received.length,done);
    assert.equal(events.filter(x=>x.phase==="AFTER").length,done);
    assert.ok(events.every(x=>x.sensorReceivedVerified===false));
    assert.ok(events.every(x=>x.dpIndexedVerified===false));
  }finally{
    controller.stopAll();
    socket.close();
  }
});

test("changing trusted delivery policy mid-session fails closed and never retries a denied packet",async()=>{
  const socket=createSocket("udp4");
  await new Promise<void>(resolve=>socket.bind(0,"127.0.0.1",resolve));
  const target={ip:"127.0.0.1",port:(socket.address() as {port:number}).port,
    protocol:"udp" as const};
  let approved=0,received=0;
  socket.on("message",()=>{received++;});
  const sink=createApprovedSensorSink({target,allowedTargets:[target],
    authorizeDelivery:async()=>++approved===1,
    auditDelivery:async()=>{},
  });
  const controller=new SyntheticSessionController({
    approveStart:async()=>true,deliver:sink,
  });
  try{
    const running=await controller.start({sample:fixture,
      approvalId:"owner-local-loopback",ratePerSecond:5,
      leaseMs:1000,maxEvents:10,
    },"test-local-actor");
    await sleep(560);
    const ended=controller.status(running.runId,"test-local-actor");
    assert.equal(ended.state,"FAILED");
    assert.equal(ended.errorCode,"TESTLAB_SINK_FAILED");
    assert.equal(received,1,"only the first explicitly authorized packet was emitted");
    assert.equal(approved,2,"no automatic retry of the denied packet");
    await sleep(270);
    assert.equal(received,1);
  }finally{
    controller.stopAll();
    socket.close();
  }
});

test("approved mixed JSON/CEF scenario sends bounded UDP datagrams and Stop halts all families",async()=>{
  const socket=createSocket("udp4");
  await new Promise<void>(resolve=>socket.bind(0,"127.0.0.1",resolve));
  const target={ip:"127.0.0.1",port:(socket.address() as {port:number}).port,
    protocol:"udp" as const};
  const output:string[]=[];
  socket.on("message",msg=>output.push(msg.toString("utf8")));
  const sink=createApprovedSensorSink({
    target,allowedTargets:[target],
    authorizeDelivery:async()=>true,
    auditDelivery:async()=>{},
  });
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:sink,
  });
  try{
    const running=await runner.start({
      scenario:{
        scenarioId:"synthetic-local-story",mode:"constant-rate",
        events:[
          {id:"firewall",sample:{
            format:"json",source:JSON.stringify({
              src_ip:"192.0.2.6",action:"deny",run_id:"old"}),
            seed:1,sequence:0,runMarkerField:"run_id",
            variableFields:[{path:"src_ip",kind:"ipv4"}],
          }},
          {id:"endpoint",sample:{
            format:"cef",
            source:"CEF:0|Synthetic|FW|1|42|Blocked|8|src=203.0.113.7 act=deny run_id=old",
            seed:2,sequence:0,runMarkerField:"run_id",
            variableFields:[{path:"src",kind:"ipv4"}],
          }},
        ],
      },
      approvalId:"owner-local-scenario",ratePerSecond:5,
      leaseMs:1500,maxEvents:12,
    },"local-scenario-owner");
    await sleep(545);
    assert.ok(output.length>=2);
    assert.ok(output[0]!.startsWith("{"));
    assert.ok(output[1]!.startsWith("CEF:0|"));
    assert.ok(output.every(x=>x.includes(running.runId)));
    const state=runner.stop(running.runId,"local-scenario-owner");
    assert.equal(state.state,"STOPPED");
    assert.equal(state.parserLifecycleNotModified,true);
    const sent=output.length;
    await sleep(290);
    assert.equal(output.length,sent);
  }finally{
    runner.stopAll();
    socket.close();
  }
});
