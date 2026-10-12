/**
 * Opt-in sensor ingestion transport boundary for Test Lab synthetic events.
 *
 * This module NEVER selects a network destination from an HTTP request:
 * an authorized in-network backend agent must construct an exact approved
 * IP-literal/protocol/port target and supply separate policy+audit functions.
 * No default target or sender is instantiated by the Parser Studio server.
 *
 * UDP/TCP kernel submission is NOT evidence of sensor reception, DP indexing,
 * parser normalization or an installed target parser.
 */
import {createSocket} from "node:dgram";
import {createConnection,isIP} from "node:net";
import type {TestLabSendContext} from "./testlab-session.js";

export type SensorProtocol="udp"|"tcp";
export type SensorTarget={ip:string;port:number;protocol:SensorProtocol};
export type SensorTransportAudit={
  phase:"BEFORE"|"AFTER"|"FAILED";
  runId:string;
  sequence:number;
  target:SensorTarget;
  byteCount:number;
  kernelSubmissionSucceeded:boolean;
  sensorReceivedVerified:false;
  runtimeParsingVerified:false;
  dpIndexedVerified:false;
};
export type ApprovedSensorSinkConfig={
  target:SensorTarget;
  allowedTargets:readonly SensorTarget[];
  /** Mandatory independently authorized target/lease policy, per event. */
  authorizeDelivery?:(context:{runId:string;sequence:number;target:SensorTarget})=>Promise<boolean>;
  /** Mandatory server-private audit; raw event never passed to it. */
  auditDelivery?:(event:SensorTransportAudit)=>Promise<void>;
  timeoutMs?:number;
};

export class SensorTransportError extends Error{
  constructor(readonly code:string){super(code);this.name="SensorTransportError";}
}
const fail=(code:string):never=>{throw new SensorTransportError(code);};
const exact=(a:SensorTarget,b:SensorTarget)=>
  a.ip===b.ip&&a.port===b.port&&a.protocol===b.protocol;

function validTarget(target:SensorTarget):boolean{
  return !!target&&typeof target==="object"&&
    typeof target.ip==="string"&&isIP(target.ip)!==0 &&
    Number.isInteger(target.port)&&target.port>=1&&target.port<=65535&&
    (target.protocol==="udp"||target.protocol==="tcp");
}
function validateSample(event:string,context:TestLabSendContext):Buffer{
  if(typeof event!=="string"||!context||typeof context!=="object"||
    typeof context.runId!=="string"||
    !/^test_run_[0-9a-f]{32}$/.test(context.runId)||
    !Number.isInteger(context.sequence)||context.sequence<0||
    !(context.signal instanceof AbortSignal))
    fail("SENSOR_SYNTHETIC_EVENT_INVALID");
  // UDP datagram must carry the raw event exactly. TCP alone uses one
  // newline frame (the bounded current receiver TCP framing contract).
  const bytes=Buffer.from(event,"utf8");
  if(bytes.length<2||bytes.length>16384||/[\u0000\r\n]/.test(event)||
    !event.includes(context.runId))
    fail("SENSOR_SYNTHETIC_EVENT_INVALID");
  return bytes;
}

function sendUdp(target:SensorTarget,payload:Buffer,signal:AbortSignal,
  timeoutMs:number):Promise<void>{
  return new Promise((resolve,reject)=>{
    const socket=createSocket(isIP(target.ip)===6?"udp6":"udp4");
    let settled=false;
    const abort=()=>done("SENSOR_DELIVERY_CANCELLED");
    const timer=setTimeout(()=>done("SENSOR_DELIVERY_TIMEOUT"),timeoutMs);
    timer.unref?.();
    function done(code?:string){
      if(settled)return;
      settled=true;clearTimeout(timer);
      signal.removeEventListener("abort",abort);
      try{socket.close();}catch{/* no repeat, socket already closed */}
      if(code)reject(new SensorTransportError(code));
      else resolve();
    }
    signal.addEventListener("abort",abort,{once:true});
    socket.on("error",()=>done("SENSOR_DELIVERY_FAILED"));
    if(signal.aborted){done("SENSOR_DELIVERY_CANCELLED");return;}
    socket.send(payload,target.port,target.ip,error=>
      done(error?"SENSOR_DELIVERY_FAILED":undefined));
  });
}

function sendTcp(target:SensorTarget,payload:Buffer,signal:AbortSignal,
  timeoutMs:number):Promise<void>{
  return new Promise((resolve,reject)=>{
    const socket=createConnection({host:target.ip,port:target.port});
    let settled=false;
    const abort=()=>done("SENSOR_DELIVERY_CANCELLED");
    const timer=setTimeout(()=>done("SENSOR_DELIVERY_TIMEOUT"),timeoutMs);
    timer.unref?.();
    function done(code?:string){
      if(settled)return;
      settled=true;clearTimeout(timer);
      signal.removeEventListener("abort",abort);
      if(code)socket.destroy();
      if(code)reject(new SensorTransportError(code));
      else resolve();
    }
    signal.addEventListener("abort",abort,{once:true});
    socket.on("error",()=>done("SENSOR_DELIVERY_FAILED"));
    socket.on("close",()=>done(signal.aborted?"SENSOR_DELIVERY_CANCELLED":undefined));
    socket.on("connect",()=>{
      if(signal.aborted){done("SENSOR_DELIVERY_CANCELLED");return;}
      // One framed newline-delimited raw event, no automatic retries.
      socket.end(payload);
    });
    if(signal.aborted)done("SENSOR_DELIVERY_CANCELLED");
  });
}

export function createApprovedSensorSink(config:ApprovedSensorSinkConfig):
  (event:string,context:TestLabSendContext)=>Promise<void>{
  if(!config||!validTarget(config.target))
    fail("SENSOR_IP_LITERAL_REQUIRED");
  if(!Array.isArray(config.allowedTargets)||
    config.allowedTargets.length>100||
    !config.allowedTargets.some(target=>validTarget(target)&&exact(target,config.target)))
    fail("SENSOR_TARGET_NOT_APPROVED");
  if(typeof config.authorizeDelivery!=="function"||
    typeof config.auditDelivery!=="function")
    fail("SENSOR_TRUST_POLICY_REQUIRED");
  const timeoutMs=config.timeoutMs??4000;
  if(!Number.isInteger(timeoutMs)||timeoutMs<250||timeoutMs>10000)
    fail("SENSOR_TIMEOUT_INVALID");
  // Own copies guard against accidental reconfiguration of the caller's
  // mutable target object after the transport is created.
  const target:Object=Object.freeze({...config.target});
  const destination=target as SensorTarget;
  const authorize=config.authorizeDelivery!;
  const audit=config.auditDelivery!;
  return async(event,context)=>{
    const rawPayload=validateSample(event,context);
    const payload=destination.protocol==="tcp"?
      Buffer.concat([rawPayload,Buffer.from("\n","utf8")]):rawPayload;
    if(payload.length>16384)fail("SENSOR_SYNTHETIC_EVENT_INVALID");
    if(context.signal.aborted)fail("SENSOR_DELIVERY_CANCELLED");
    let allowed=false;
    try{allowed=await authorize({
      runId:context.runId,sequence:context.sequence,target:destination,
    });}catch{/* policy failures deny egress without attempting a socket */}
    if(allowed!==true)fail("SENSOR_DELIVERY_NOT_APPROVED");
    if(context.signal.aborted)fail("SENSOR_DELIVERY_CANCELLED");
    const base={
      runId:context.runId,sequence:context.sequence,target:destination,
      byteCount:payload.length,
      sensorReceivedVerified:false as const,
      runtimeParsingVerified:false as const,
      dpIndexedVerified:false as const,
    };
    try{await audit({phase:"BEFORE",...base,kernelSubmissionSucceeded:false});}
    catch{fail("SENSOR_AUDIT_UNAVAILABLE");}
    if(context.signal.aborted)fail("SENSOR_DELIVERY_CANCELLED");
    try{
      if(destination.protocol==="udp")
        await sendUdp(destination,payload,context.signal,timeoutMs);
      else await sendTcp(destination,payload,context.signal,timeoutMs);
    }catch(error){
      try{await audit({phase:"FAILED",...base,kernelSubmissionSucceeded:false});}
      catch{/* do not echo raw vendor/audit errors */}
      if(error instanceof SensorTransportError)throw error;
      fail("SENSOR_DELIVERY_FAILED");
    }
    try{await audit({phase:"AFTER",...base,kernelSubmissionSucceeded:true});}
    catch{fail("SENSOR_AUDIT_UNAVAILABLE");}
  };
}
