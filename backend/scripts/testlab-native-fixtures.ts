/**
 * Fixed public synthetic test lab fixture emitter to stdout only.
 * No customer event, destination IP, API Key, network or durable storage.
 */
import {createSyntheticPreview} from "../src/testlab-synthetic.js";
const now=Date.parse("2026-10-12T01:02:03Z");
const json=createSyntheticPreview({
  format:"json",
  source:JSON.stringify({
    source:{ip:"192.0.2.11"},
    destination:{ip:"198.51.100.8",port:"443"},
    action:"deny",event:{id:"83",time:"2026-01-01T02:03:04Z"},
  }),
  seed:2718,sequence:10,timestampField:"event.time",
  variableFields:[{path:"source.ip",kind:"ipv4"},
    {path:"destination.ip",kind:"ipv4"}],
},now);
const kv=createSyntheticPreview({
  format:"kv",
  source:"src_ip=203.0.113.12 dst_port=443 action=deny event_time=2026-01-01T02:03:04Z user=synthetic-old",
  seed:2718,sequence:11,timestampField:"event_time",
  variableFields:[{path:"src_ip",kind:"ipv4"},{path:"user",kind:"username"}],
},now);
const csv=createSyntheticPreview({
  format:"csv",
  source:'192.0.2.12,443,"deny"',
  csvColumns:["src_ip","dst_port","action"],csvDelimiter:",",
  seed:2718,sequence:12,
  variableFields:[{path:"src_ip",kind:"ipv4"}],
},now);
const cef=createSyntheticPreview({
  format:"cef",
  source:"CEF:0|Synthetic|FW|1|42|Denied\\|Policy|8|src=192.0.2.10 dpt=443 act=deny rt=2025-01-01T01:02:03Z",
  seed:2718,sequence:13,timestampField:"rt",
  variableFields:[{path:"src",kind:"ipv4"}],
},now);
const leef=createSyntheticPreview({
  format:"leef",
  source:"LEEF:2.0|Synthetic|FW|1|501|0x5E|src=203.0.113.10^dstPort=443^act=deny^rt=2025-01-01T01:02:03Z",
  seed:2718,sequence:14,timestampField:"rt",
  variableFields:[{path:"src",kind:"ipv4"}],
},now);
const leef1=createSyntheticPreview({
  format:"leef",
  source:"LEEF:1.0|Synthetic|FW|1|500|src=203.0.113.12\tdstPort=443\tact=deny",
  seed:2718,sequence:15,
  variableFields:[{path:"src",kind:"ipv4"}],
},now);
const syslog=createSyntheticPreview({
  format:"syslog_rfc5424",syslogBodyFormat:"kv",
  source:"<165>1 2025-01-01T01:02:03Z synthetic-edge01 firewall 123 ID42 - src_ip=198.51.100.5 action=deny",
  seed:2718,sequence:16,timestampField:"syslog_timestamp",
  variableFields:[{path:"body.src_ip",kind:"ipv4"}],
},now);
if([json,kv,csv,cef,leef,leef1,syslog].some(event=>event.safeToSendToSensor!==false||
  event.runtimeParsingVerified!==false||event.targetSensorVerified!==false))
  throw new Error("Synthetic preview has unexpected network readiness");
process.stdout.write(JSON.stringify({json,kv,csv,cef,leef,leef1,syslog})+"\n");
