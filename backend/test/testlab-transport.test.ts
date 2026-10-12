import test from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import {createServer, type AddressInfo} from "node:net";
import {
  createApprovedSensorSink, type SensorTransportAudit,
} from "../src/testlab-transport.js";

const runId="test_run_aabbccddeeff00112233445566778899";
const context=(signal=new AbortController().signal)=>({runId,sequence:2,signal});
const sample=JSON.stringify({test:{run_id:runId},
  source:{ip:"192.0.2.12"},action:"deny"});
const clock=Date.now;

test("approved loopback UDP delivery sends exactly one synthetic packet, with safe audit",async()=>{
  const receiver=dgram.createSocket("udp4");
  await new Promise<void>(resolve=>receiver.bind(0,"127.0.0.1",resolve));
  const port=(receiver.address() as {port:number}).port;
  const events:SensorTransportAudit[]=[];
  try{
    const received=new Promise<string>((resolve,reject)=>{
      receiver.once("message",msg=>resolve(msg.toString("utf8")));
      receiver.once("error",reject);
    });
    const sink=createApprovedSensorSink({
      target:{ip:"127.0.0.1",port,protocol:"udp"},
      allowedTargets:[{ip:"127.0.0.1",port,protocol:"udp"}],
      authorizeDelivery:async()=>true,
      auditDelivery:async item=>{events.push(item);},
    });
    await sink(sample,context());
    assert.equal(await received,sample,"UDP must transmit one raw datagram without newline");
    assert.deepEqual(events.map(x=>x.phase),["BEFORE","AFTER"]);
    assert.ok(events.every(e=>e.sensorReceivedVerified===false));
    assert.ok(events.every(e=>e.runtimeParsingVerified===false));
    assert.equal(JSON.stringify(events).includes("192.0.2.12"),false);
    assert.equal(events[1]?.byteCount,Buffer.byteLength(sample,"utf8"));
  }finally{receiver.close();}
});

test("approved loopback TCP delivery sends one framed event then closes",async()=>{
  let content="";
  const server=createServer(socket=>{
    socket.on("data",bytes=>{content+=bytes.toString("utf8");});
  });
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  const port=(server.address() as AddressInfo).port;
  try{
    const sink=createApprovedSensorSink({
      target:{ip:"127.0.0.1",port,protocol:"tcp"},
      allowedTargets:[{ip:"127.0.0.1",port,protocol:"tcp"}],
      authorizeDelivery:async()=>true,
      auditDelivery:async()=>{},
    });
    await sink(sample,context());
    assert.equal(content,sample+"\n");
  }finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
});

test("never send without exact trusted destination allowlist and audit/authorization policy",async()=>{
  const target={ip:"127.0.0.1",port:42199,protocol:"udp" as const};
  assert.throws(()=>createApprovedSensorSink({
    target,allowedTargets:[],authorizeDelivery:async()=>true,auditDelivery:async()=>{},
  }),/SENSOR_TARGET_NOT_APPROVED/);
  assert.throws(()=>createApprovedSensorSink({
    target:{ip:"localhost",port:42199,protocol:"udp"},
    allowedTargets:[target],authorizeDelivery:async()=>true,auditDelivery:async()=>{},
  }),/SENSOR_IP_LITERAL_REQUIRED/);
  assert.throws(()=>createApprovedSensorSink({
    target,allowedTargets:[target],authorizeDelivery:async()=>true,
  }),/SENSOR_TRUST_POLICY_REQUIRED/);
  assert.throws(()=>createApprovedSensorSink({
    target,allowedTargets:[target],auditDelivery:async()=>{},
  }),/SENSOR_TRUST_POLICY_REQUIRED/);
  let audits=0;
  const denied=createApprovedSensorSink({target,allowedTargets:[target],
    authorizeDelivery:async()=>false,
    auditDelivery:async()=>{audits++;},
  });
  await assert.rejects(()=>denied(sample,context()),/SENSOR_DELIVERY_NOT_APPROVED/);
  assert.equal(audits,0);
});

test("sender refuses real-looking/raw input without matching run ID, unsafe framing or aborted signal",async()=>{
  const target={ip:"127.0.0.1",port:42199,protocol:"udp" as const};
  let audits=0,granted=0;
  const sink=createApprovedSensorSink({
    target,allowedTargets:[target],
    authorizeDelivery:async()=>{granted++;return true;},
    auditDelivery:async()=>{audits++;},
  });
  for(const bad of [
    JSON.stringify({action:"deny",message:"no marker"}),
    sample+"\n"+sample,
    sample+"\u0000",
    "x".repeat(17000),
  ])await assert.rejects(()=>sink(bad,context()),/SENSOR_SYNTHETIC_EVENT_INVALID/);
  const aborted=new AbortController();
  aborted.abort();
  await assert.rejects(()=>sink(sample,context(aborted.signal)),/SENSOR_DELIVERY_CANCELLED/);
  assert.equal(granted,0);
  assert.equal(audits,0);
});

test("audit sink failure prevents network attempt; vendor target remains independently unverified",async()=>{
  const target={ip:"127.0.0.1",port:42199,protocol:"udp" as const};
  const sink=createApprovedSensorSink({
    target,allowedTargets:[target],
    authorizeDelivery:async()=>true,
    auditDelivery:async()=>{throw Error("DO_NOT_ECHO_FROM_AUDIT");},
  });
  await assert.rejects(()=>sink(sample,context()),(e:unknown)=>
    e instanceof Error && e.message==="SENSOR_AUDIT_UNAVAILABLE");
});
