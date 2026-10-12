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
if([json,kv,csv].some(event=>event.safeToSendToSensor!==false||
  event.runtimeParsingVerified!==false||event.targetSensorVerified!==false))
  throw new Error("Synthetic preview has unexpected network readiness");
process.stdout.write(JSON.stringify({json,kv,csv})+"\n");
