import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";

const jsonFragment=readFileSync(new URL("../templates/ruby-fragment.rb.tpl",import.meta.url),"utf8");
const jsonStart=jsonFragment.indexOf('def parserstudio_json_duplicate_keys?(raw)');
const jsonEnd=jsonFragment.indexOf('\ndef parserstudio_unescape(text)',jsonStart);
assert.ok(jsonStart>=0&&jsonEnd>jsonStart,'The compiled JSON duplicate guard must remain available');
const sharedJsonDecoder=jsonFragment.slice(jsonStart,jsonEnd);
// Standalone native helper acceptance uses the exact shared parser code
// from the compiled Ruby fragment, not a permissive JSON.parse substitute.
const helper=sharedJsonDecoder+'\n'+
  readFileSync(new URL("../templates/generic-structural-helper.rb.tpl",import.meta.url),"utf8");
const rubyAvailable=spawnSync("ruby",["-v"],{encoding:"utf8"}).status===0;

function runRuby(method:string,raw:string):unknown{
  const source=[
    "require 'json'","require 'csv'","require 'base64'","require 'ipaddr'","require 'time'",
    helper,
    // The strict JSON decoder relies on an initialized compiler runtime.
    // Standalone source probes must use the same bounded JSON depth policy.
    "@parser_rule_set = {'extraction'=>{'format'=>'generic_structural','maxDepth'=>8}}",
    `result = ${method}(${JSON.stringify(raw)})`,
    "STDOUT.write(JSON.generate(result))",
  ].join("\n");
  const out=spawnSync("ruby",["-e",source],{encoding:"utf8",timeout:5000,maxBuffer:1024*1024});
  assert.equal(out.status,0,out.stderr || String(out.error));
  return JSON.parse(out.stdout);
}


test("Generic Structural positional CSV has one Ruby2.4-compatible shared IPv4 validator",()=>{
  // Enforce a shared semantic path even when Ruby is unavailable on a local
  // workstation. The pinned target Ruby 2.4 CI and live DP acceptance execute
  // the generated code rather than trusting this source-level guard alone.
  assert.match(helper,/def parserstudio_generic_valid_ipv4\?\(value\)/);
  assert.match(helper,/candidate\.split\('\.'\)\.all\? \{ \|part\| Integer\(part, 10\)\.between\?\(0, 255\) \}/);
  assert.match(helper,/rescue ArgumentError\s+false\s+end/);
  assert.match(helper,/values\[index\]\)/);
  assert.match(helper,/ips = values\.count \{ \|value\| parserstudio_generic_valid_ipv4\?\(value\) \}/);
  const positional=helper.slice(helper.indexOf('def parserstudio_generic_rfc3164_positional_csv(text)'),
    helper.indexOf('def parserstudio_generic_envelope_pri(pri_text)'));
  assert.doesNotMatch(positional,/rescue ArgumentError/);
  // 125-column PAN-OS original from public docs must not be refused by
  // the Ruby source handler when its independent envelope accepts up to 150.
  assert.match(positional,/values\.length\.between\?\(12, 150\)/);
});

test("Generic Structural shared native IPv4 validator refuses invalid octets",{skip:!rubyAvailable},()=>{
  assert.equal(runRuby("parserstudio_generic_valid_ipv4?","10.10.20.15"),true);
  assert.equal(runRuby("parserstudio_generic_valid_ipv4?","0.0.0.0"),true);
  assert.equal(runRuby("parserstudio_generic_valid_ipv4?","255.255.255.255"),true);
  assert.equal(runRuby("parserstudio_generic_valid_ipv4?","256.10.20.15"),false);
  assert.equal(runRuby("parserstudio_generic_valid_ipv4?","1.2.3"),false);
  assert.equal(runRuby("parserstudio_generic_valid_ipv4?","10.10.10.1/24"),false);
});

test("Generic Structural helper keeps Syslog envelope parsing ahead of weak generic fallbacks",()=>{
  assert.match(helper,/def parserstudio_generic_syslog_envelope\(text\)/);
  assert.match(helper,/def parserstudio_generic_syslog_envelope_structured\(text\)/);
  assert.match(helper,/rfc3164_year_before_time/);
  assert.match(helper,/rfc3164_year_after_time/);
  assert.match(helper,/syslog_envelope_positional_csv/);
  assert.match(helper,/panos_traffic_csv/);
  const envelope=helper.indexOf("result = parserstudio_generic_syslog_envelope_structured(text)");
  const comma=helper.indexOf("result = parserstudio_generic_comma_kv(text)");
  const delimited=helper.indexOf("result = parserstudio_generic_delimited_comma_kv(text)");
  assert.ok(envelope>=0&&comma>envelope&&delimited>envelope);
});

// Individual grammar probes return nil for unsupported records. The top-level
// dispatcher instead raises ArgumentError and must never silently complete.
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
  assert.throws(()=>runRuby("parserstudio_generic_structural",checkpoint+"unexpected"),/Unsupported generic structural event/);
});


test("Generic Structural common firewall wrappers cover year-bearing ASA and RFC3164 positional CSV",{skip:!rubyAvailable},()=>{
  const asa='<166>Oct 15 2026 00:05:03 ASA-EDGE01 : %ASA-6-302013: Built outbound TCP connection 18745213 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)';
  const parsedAsa=runRuby("parserstudio_generic_structural",asa) as any;
  assert.deepEqual(parsedAsa.syslog,{
    app_tag:"%ASA-6-302013",pri:"166",month:"Oct",day:"15",year:"2026",
    time:"00:05:03",hostname:"ASA-EDGE01",
  });
  assert.equal(parsedAsa.asa.connection_id,"18745213");
  assert.equal(parsedAsa.asa.src_ip,"203.0.113.50");
  assert.equal(parsedAsa.asa.dst_ip,"10.1.15.27");

  const pan='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy';
  const parsedPan=runRuby("parserstudio_generic_structural",pan) as any;
  assert.deepEqual(parsedPan.syslog,{pri:"14",month:"Oct",day:"15",time:"00:03:21",hostname:"PA-FW01"});
  assert.equal(parsedPan.generic.mode,"panos_traffic_csv");
  assert.equal(parsedPan.generic.source_raw,pan);
  assert.equal(parsedPan.generic.fields.domain,"1");
  assert.equal(parsedPan.generic.fields.type,"TRAFFIC");
  assert.equal(parsedPan.generic.fields.src,"10.10.20.15");
  assert.equal(parsedPan.generic.fields.sport,"51234");
  assert.equal(parsedPan.generic.fields.dport,"443");
  assert.equal(parsedPan.generic.fields.action,"allow");
  assert.equal(parsedPan.generic.fields.action_source,"from-policy");
});

test("Generic Structural V15 Ruby helper parses bounded BSD bracket-id messages",{skip:!rubyAvailable},()=>{
  const raw='Mar 26 10:20:16 ssb SNMPD_CONTEXT_ERROR: [7400]: emq: isiu: success in 6237 context 5367';
  const parsed=runRuby("parserstudio_generic_structural",raw) as any;
  assert.deepEqual(parsed.syslog,{month:"Mar",day:"26",time:"10:20:16",hostname:"ssb",app_tag:"SNMPD_CONTEXT_ERROR"});
  assert.equal(parsed.generic.mode,"bsd_bracket_pid_message");
  assert.equal(parsed.generic.source_raw,raw);
  assert.equal(parsed.generic.pid,"7400");
  assert.equal(runRuby("parserstudio_generic_bsd_bracket_pid_message",raw.replace("Mar 26","Mar 32")),null);
  assert.equal(runRuby("parserstudio_generic_bsd_bracket_pid_message",raw.replace("[7400]","[123456789]")),null);
});

test("Generic Structural V14 Ruby helper parses bounded dual timestamp session envelopes",{skip:!rubyAvailable},()=>{
  const raw='Oct 19 09:11:55 edge-node 1 2026-10-19T09:11:55+02:00 192.0.2.3 SecureAccess: - - - 2026-10-19 09:11:55 - edge-node - [198.51.100.10] user.name(REALM)[ROLE] - Session established successfully';
  const parsed=runRuby("parserstudio_generic_structural",raw) as any;
  assert.equal(parsed.syslog.timestamp,"2026-10-19T09:11:55+02:00");
  assert.equal(parsed.syslog.app_tag,"SecureAccess");
  assert.equal(parsed.session_envelope.client,"198.51.100.10");
  assert.equal(parsed.session_envelope.identity,"user.name(REALM)[ROLE]");
  assert.equal(parsed.session_envelope.source_raw,raw);
  assert.equal(runRuby("parserstudio_generic_dual_timestamp_session",raw.replace("Oct 19 09:11:55","Oct 32 09:11:55")),null);
  assert.equal(runRuby("parserstudio_generic_dual_timestamp_session",raw.replace(" - - - "," - x - ")),null);
});

test("Generic Structural V13 Ruby helper parses bounded ISO PRI positional messages",{skip:!rubyAvailable},()=>{
  const raw='<134>2026-10-16 03:11:07.915 +0200 edge SYS APS INFO 19034 Num clients to walk : 0';
  const parsed=runRuby("parserstudio_generic_structural",raw) as any;
  assert.deepEqual(parsed.syslog,{pri:"134",date:"2026-10-16",time:"03:11:07.915",timezone:"+0200"});
  assert.equal(parsed.generic.mode,"iso_pri_positional");
  assert.equal(parsed.generic.source_raw,raw);
  assert.deepEqual(parsed.generic.tokens.slice(0,5),["edge","SYS","APS","INFO","19034"]);
  assert.equal(runRuby("parserstudio_generic_iso_pri_positional",raw.replace("<134>","<192>")),null);
  assert.equal(runRuby("parserstudio_generic_iso_pri_positional",raw.replace("+0200","+2500")),null);
  assert.equal(runRuby("parserstudio_generic_iso_pri_positional",raw.replace("SYS","system")),null);
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

test("Generic Structural IP tokens do not reinterpret decimal ports as addresses",{skip:!rubyAvailable},()=>{
  assert.equal(runRuby("parserstudio_generic_ip_token","61507"),false);
  assert.equal(runRuby("parserstudio_generic_ip_token","443"),false);
  assert.equal(runRuby("parserstudio_generic_ip_token","192.0.2.1"),true);
  assert.equal(runRuby("parserstudio_generic_ip_token","2001:db8::1"),true);
});

test("ISO Syslog variants share a non-normalizing calendar/clock guard",()=>{
  assert.match(helper,/def parserstudio_generic_iso_calendar_valid\(date, clock, zone\)/);
  assert.match(helper,/parsed\.strftime\('%Y-%m-%d'\) == date/);
  assert.match(helper,/parsed\.strftime\('%H:%M:%S'\) == clock\[0, 8\]/);
  assert.equal((helper.match(/parserstudio_generic_iso_calendar_valid\(match\[2\],match\[3\],normalized_zone\)/g)||[]).length,2);
});

test("Generic Structural V11 Ruby helper parses bounded ISO PRI mixed positional logs",{skip:!rubyAvailable},()=>{
  const raw='<129>2026-10-15 14:54:44.502 +0100 edge WAF ALERT CODE 192.0.2.1 61507 198.51.100.2 443 app policy LOG NONE token1 token2 token3 token4 "-" "multi word positional value" token7 token8';
  const parsed=runRuby("parserstudio_generic_structural",raw) as any;
  assert.deepEqual(parsed.syslog,{pri:"129",date:"2026-10-15",time:"14:54:44.502",timezone:"+0100"});
  assert.deepEqual(parsed.generic.tokens.slice(0,8),["edge","WAF","ALERT","CODE","192.0.2.1","61507","198.51.100.2","443"]);
  assert.ok(parsed.generic.tokens.includes("-"));
  assert.ok(parsed.generic.tokens.includes("multi word positional value"));
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("<129>","<192>")),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("+0100","+2500")),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("2026-10-15","2026-02-30")),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("2026-10-15","2026-02-29")),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("14:54:44","25:54:44")),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",'<129>2026-10-15 14:54:44.502 +0100 edge short 192.0.2.1 198.51.100.2'),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("198.51.100.2","not-an-ip")),/Unsupported generic structural event/);
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
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace("<134>","<192>")),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",'<134>date=2023-02-23 time=22:49:29 type=event subtype=system'),/Unsupported generic structural event/);
  assert.throws(()=>runRuby("parserstudio_generic_structural",raw.replace('desc="User login successful"','desc="User login successful')),/Unsupported generic structural event/);
});

test("Generic Structural V10 Ruby helper rejects prototype-bearing keys",{skip:!rubyAvailable},()=>{
  const comma='<180>Mar 3 10:42:25 ise-host APP 0001 1 0 2022-03-03 10:42:25.842 +00:00 0002 WARN Connector: ok, AD-Domain=host.local, constructor=bad';
  assert.equal(runRuby("parserstudio_generic_comma_kv",comma),null);
  const spaced='device="SFW" date=2017-01-31 time=14:16:19 timezone="IST" constructor=bad status="Allow"';
  assert.equal(runRuby("parserstudio_generic_space_kv",spaced),null);
});
