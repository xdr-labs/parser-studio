import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";

const helper=readFileSync(new URL("../templates/generic-structural-helper.rb.tpl",import.meta.url),"utf8");
const rubyAvailable=spawnSync("ruby",["-v"],{encoding:"utf8"}).status===0;

function runRuby(method:string,raw:string):unknown{
  const source=[
    "require 'json'","require 'csv'","require 'base64'","require 'ipaddr'","require 'time'",
    helper,
    `result = ${method}(${JSON.stringify(raw)})`,
    "STDOUT.write(JSON.generate(result))",
  ].join("\n");
  const out=spawnSync("ruby",["-e",source],{encoding:"utf8",timeout:5000,maxBuffer:1024*1024});
  assert.equal(out.status,0,out.stderr || String(out.error));
  return JSON.parse(out.stdout);
}

test("Generic Structural V9 Ruby helper matches bounded WatchGuard, Juniper and secure-email grammars",{skip:!rubyAvailable},()=>{
  const watchguard='<139>Jan 16 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 (2024-01-19T08:48:15) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25 msg="SMTP request" proxy_act="SMTP-Outgoing.1" rcvd_bytes="272" sent_bytes="282" sender="tester@testnet.com" recipients="wg@localhost" (SMTP-proxy-00)';
  const wg=runRuby("parserstudio_generic_structural",watchguard) as any;
  assert.equal(wg.watchguard_header.hostname,"WatchGuard-Firebox");
  assert.deepEqual(wg.watchguard.tokens.slice(0,4),["Allow","1-Trusted","0-External","tcp"]);
  assert.equal(wg.watchguard.kv.msg_id,"1BFF-000F");
  assert.deepEqual(wg.watchguard.groups,["SMTP-proxy-00"]);

  const juniper='Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.83.99/40275->192.168.32.1/161 None 192.168.83.99/40275->192.168.32.1/161 None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255';
  const jn=runRuby("parserstudio_generic_structural",juniper) as any;
  assert.equal(jn.syslog.app_tag,"RT_FLOW");
  assert.equal(jn.juniper.event,"RT_FLOW_SESSION_CREATE");
  assert.equal(jn.juniper.tokens.length,14);

  const mail="Info: Response received for file reputation query from Cloud. FileName = 'mod-6.exe', MID = 5, Disposition = MALICIOUS, Malware = W32.TEST, Reputation Score = 73, sha256 = "+"a".repeat(64)+", upload_action = 2";
  const se=runRuby("parserstudio_generic_structural",mail) as any;
  assert.equal(se.generic.mode,"delimited_kv");
  assert.equal(se.generic.fields.MID,"5");
  assert.equal(se.generic.fields["Reputation Score"],"73");
  assert.deepEqual(se.generic.prefix_tokens.slice(0,2),["Info","Response"]);

  const wrapped="<166>Mar 17 18:24:37 mailhost: Info: Prefix words. Name = 'sample.exe', ID = 5, Size = 10, Type = binary";
  const sw=runRuby("parserstudio_generic_structural",wrapped) as any;
  assert.deepEqual(sw.syslog,{pri:"166",month:"Mar",day:"17",time:"18:24:37",host:"mailhost:",tag:"Info"});
  assert.deepEqual(sw.generic.prefix_tokens,["Prefix","words."]);
  assert.equal(sw.generic.fields.ID,"5");

  const prefixed='darktrace {"model":{"name":"Test Model"},"device":{"ip":"192.0.2.10"}}';
  const pj=runRuby("parserstudio_generic_structural",prefixed) as any;
  assert.equal(pj.generic.mode,"prefixed_json");
  assert.equal(pj.generic.prefix,"darktrace");
  assert.equal(pj.body.device.ip,"192.0.2.10");
  assert.equal(runRuby("parserstudio_generic_prefixed_json",'darktrace {"model":'),null);
  assert.equal(runRuby("parserstudio_generic_prefixed_json",'darktrace [1,2,3]'),null);

  const checkpoint='<134>1 2020-03-30T07:20:35Z gw CheckPoint 8363 - [flags:"1"; sys_message::"risk"]  ';
  const cp=runRuby("parserstudio_generic_structural",checkpoint) as any;
  assert.equal(cp.body.flags,"1");
  assert.equal(cp.body["sys_message:"],"risk");
  assert.equal(runRuby("parserstudio_generic_structural",checkpoint+"unexpected"),null);
});

test("Generic Structural V12 Ruby helper parses bounded WatchGuard free-form messages",{skip:!rubyAvailable},()=>{
  const alarm='<142>May 10 15:19:05 WatchGuard-Firebox (2024-05-10T09:49:05) firewall: msg_id="3000-0152" IPv4 source route attack from 10.0.1.34 detected. (IPS)';
  const diagnostic='<142>May 10 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 (2024-05-10T09:49:05) firewall[10]: msg_id="3000-0006" Application control settings updated';
  const a=runRuby("parserstudio_generic_structural",alarm) as any;
  assert.equal(a.watchguard_header.pri,"142");
  assert.equal(a.watchguard_header.app_tag,"firewall");
  assert.equal(a.watchguard_message.msg_id,"3000-0152");
  assert.equal(a.watchguard_message.message,"IPv4 source route attack from 10.0.1.34 detected. (IPS)");
  assert.equal(a.watchguard_message.source_raw,alarm);
  const d=runRuby("parserstudio_generic_structural",diagnostic) as any;
  assert.equal(d.watchguard_header.serial,"FVE6035FD3AE3");
  assert.equal(d.watchguard_header.app_tag,"firewall[10]");
  assert.equal(d.watchguard_message.source_raw,diagnostic);
  assert.equal(runRuby("parserstudio_generic_watchguard_message",alarm.replace("<142>","<192>")),null);
  assert.equal(runRuby("parserstudio_generic_watchguard_message",alarm.replace("3000-0152","bad-id")),null);
});

test("Generic Structural V11 Ruby helper parses bounded ISO PRI mixed positional logs",{skip:!rubyAvailable},()=>{
  const raw='<129>2026-10-15 14:54:44.502 +0100 edge WAF ALERT CODE 192.0.2.1 61507 198.51.100.2 443 app policy LOG NONE token1 token2 token3 token4 "-" "multi word positional value" token7 token8';
  const parsed=runRuby("parserstudio_generic_structural",raw) as any;
  assert.deepEqual(parsed.syslog,{pri:"129",date:"2026-10-15",time:"14:54:44.502",timezone:"+0100"});
  assert.deepEqual(parsed.generic.tokens.slice(0,8),["edge","WAF","ALERT","CODE","192.0.2.1","61507","198.51.100.2","443"]);
  assert.ok(parsed.generic.tokens.includes("-"));
  assert.ok(parsed.generic.tokens.includes("multi word positional value"));
  assert.equal(runRuby("parserstudio_generic_structural",raw.replace("<129>","<192>")),null);
  assert.equal(runRuby("parserstudio_generic_structural",raw.replace("+0100","+2500")),null);
  assert.equal(runRuby("parserstudio_generic_structural",raw.replace("2026-10-15","2026-02-30")),null);
  assert.equal(runRuby("parserstudio_generic_structural",'<129>2026-10-15 14:54:44.502 +0100 edge short 192.0.2.1 198.51.100.2'),null);
  assert.equal(runRuby("parserstudio_generic_structural",raw.replace("198.51.100.2","not-an-ip")),null);
});

test("Generic Structural V10 Ruby helper parses bounded PRI-prefixed space KV",{skip:!rubyAvailable},()=>{
  const raw='<134>date=2023-02-23 time=22:49:29 tz="+0500" devname=FMG-VM device_id=FMG001 log_id=0001010018 type=event subtype=system pri=information desc="User login successful" msg="inner status=embedded value" status=success';
  const parsed=runRuby("parserstudio_generic_structural",raw) as any;
  assert.equal(parsed.syslog.pri,"134");
  assert.equal(parsed.generic.mode,"space_kv");
  assert.equal(parsed.generic.source_raw,raw);
  assert.equal(parsed.generic.kv.device_id,"FMG001");
  assert.equal(parsed.generic.kv.desc,"User login successful");
  assert.equal(parsed.generic.kv.msg,"inner status=embedded value");
  assert.equal(parsed.generic.kv.status,"success");
  assert.equal(runRuby("parserstudio_generic_structural",raw.replace("<134>","<192>")),null);
  assert.equal(runRuby("parserstudio_generic_structural",'<134>date=2023-02-23 time=22:49:29 type=event subtype=system'),null);
  assert.equal(runRuby("parserstudio_generic_structural",raw.replace('desc="User login successful"','desc="User login successful')),null);
});

test("Generic Structural V10 Ruby helper rejects prototype-bearing keys",{skip:!rubyAvailable},()=>{
  const comma='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: ok, AD-Domain=host.local, constructor=bad';
  assert.equal(runRuby("parserstudio_generic_comma_kv",comma),null);
  const spaced='device="SFW" date=2017-01-31 time=14:16:19 timezone="IST" constructor=bad status="Allow"';
  assert.equal(runRuby("parserstudio_generic_space_kv",spaced),null);
});
