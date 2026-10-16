export type PocBodyKind='csv'|'kv'|'json'|'cef'|'leef'|'message';

export interface SyslogPocCase{
  id:string;
  family:string;
  raw:string;
  bodyKind:PocBodyKind;
  expectedPri?:string;
  expectedHost?:string;
}

const bodies={
  panos:'1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/16 15:44:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/16 15:43:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy',
  fortinet:'fortigate: date=2026-10-16 time=15:44:21 devname=FGT01 devid=FGT60FTK123456 type=traffic subtype=forward level=notice srcip=10.10.10.10 dstip=198.51.100.20 srcport=51514 dstport=443 proto=6 action=accept',
  sonicwall:'firewall: id=firewall sn=0017C5001234 time="2026-10-16 15:44:21" fw=192.0.2.1 pri=6 c=1024 m=537 msg="Connection opened" src=10.1.1.10 dst=198.51.100.50',
  suricata:'suricata[445]: {"timestamp":"2026-10-16T15:44:21.123456+0900","event_type":"alert","src_ip":"10.1.1.10","dest_ip":"198.51.100.20","alert":{"signature":"ET TEST"}}',
  cef:'edr: CEF:0|ExampleEDR|Endpoint|1.0|1001|Malware detected|8|src=10.1.1.10 dst=198.51.100.20 suser=alice',
  leef:'proxy: LEEF:2.0|ExampleProxy|Cloud|1.0|blocked|devTime=2026-10-16T15:44:21Z\tsrc=10.1.1.10\tdst=198.51.100.20',
  snort:'snort[771]: [1:1000001:1] TEST TCP scan [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.1.1.10:51514 -> 198.51.100.20:443',
  pfsense:'filterlog[882]: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,41301,0,none,6,tcp,60,10.1.1.10,198.51.100.20,51514,443,0,S,12345,,64240,,mss',
};

const fixtures:Array<[string,string,PocBodyKind,string]>= [
  ['panos',bodies.panos,'csv','PA-FW01'],
  ['fortinet',bodies.fortinet,'kv','FGT01'],
  ['sonicwall',bodies.sonicwall,'kv','SMA01'],
  ['suricata',bodies.suricata,'json','IDS01'],
  ['cef-edr',bodies.cef,'cef','EDR01'],
  ['leef-proxy',bodies.leef,'leef','PROXY01'],
  ['snort',bodies.snort,'message','IDS02'],
  ['pfsense',bodies.pfsense,'csv','FWBSD01'],
];

const cases:SyslogPocCase[]=[];

for(const [family,body,bodyKind,host] of fixtures){
  cases.push({
    id:`${family}-rfc3164`,family,bodyKind,
    raw:`<14>Oct 16 15:44:21 ${host} ${body}`,expectedPri:'14',expectedHost:host,
  });
  cases.push({
    id:`${family}-rfc3164-year-before-time`,family,bodyKind,
    raw:`<14>Oct 16 2026 15:44:21 ${host} ${body}`,expectedPri:'14',expectedHost:host,
  });
  cases.push({
    id:`${family}-rfc3164-year-after-time`,family,bodyKind,
    raw:`<14>Oct 16 15:44:21 2026 ${host} ${body}`,expectedPri:'14',expectedHost:host,
  });
  cases.push({
    id:`${family}-rfc3339-loose`,family,bodyKind,
    raw:`<14>2026-10-16T15:44:21.123+09:00 ${host} ${body}`,expectedPri:'14',expectedHost:host,
  });
  cases.push({
    id:`${family}-iso-space-zone`,family,bodyKind,
    raw:`<14>2026-10-16 15:44:21.123 +0900 ${host} ${body}`,expectedPri:'14',expectedHost:host,
  });
}

cases.push(
  {
    id:'rfc5424-general-text',family:'generic-rfc5424',bodyKind:'message',
    raw:'<34>1 2026-10-16T15:44:21.123Z edge01 auth 123 ID47 - user login failed from 198.51.100.7',
    expectedPri:'34',expectedHost:'edge01',
  },
  {
    id:'rfc5424-json',family:'aws-waf',bodyKind:'json',
    raw:'<134>1 2026-10-16T15:44:21Z waf01 aws-waf - WAF [meta@32473 region="ap-northeast-2"] {"action":"BLOCK","clientIp":"198.51.100.7","uri":"/login"}',
    expectedPri:'134',expectedHost:'waf01',
  },
  {
    id:'rfc5424-cef',family:'endpoint-cef',bodyKind:'cef',
    raw:'<134>1 2026-10-16T15:44:21Z edr01 agent 432 ALERT - CEF:0|Vendor|EDR|1.0|42|Malware|9|src=10.0.0.8 dst=198.51.100.8',
    expectedPri:'134',expectedHost:'edr01',
  },
  {
    id:'rfc5424-leef',family:'proxy-leef',bodyKind:'leef',
    raw:'<134>1 2026-10-16T15:44:21+09:00 proxy01 nss - BLOCK - LEEF:2.0|Vendor|Proxy|1.0|block|src=10.0.0.8\tdst=198.51.100.8',
    expectedPri:'134',expectedHost:'proxy01',
  },
  {
    id:'pri-only-fortinet',family:'fortinet',bodyKind:'kv',
    raw:'<134>date=2026-10-16 time=15:44:21 devname=FGT02 devid=FGT60FTK654321 type=event subtype=system level=information action=login status=success',
    expectedPri:'134',
  },
  {
    id:'pri-only-cef',family:'cef',bodyKind:'cef',
    raw:'<134>CEF:0|Vendor|WAF|1.0|100|SQL Injection|8|src=10.0.0.9 dst=198.51.100.9 request=/login',
    expectedPri:'134',
  },
  {
    id:'pri-only-leef',family:'leef',bodyKind:'leef',
    raw:'<134>LEEF:2.0|Vendor|NDR|1.0|dns|src=10.0.0.9\tdst=198.51.100.53',
    expectedPri:'134',
  },
  {
    id:'slash-date-security-json',family:'ndr-json',bodyKind:'json',
    raw:'<134>2026/10/16 15:44:21 NDR01 detector: {"event":"anomaly","src":"10.0.0.2","dst":"198.51.100.2"}',
    expectedPri:'134',expectedHost:'NDR01',
  },
  {
    id:'sophos-colon-date-kv',family:'sophos',bodyKind:'kv',
    raw:'2026:10:16-15:44:21 SOPHOS01 ulogd[12511]: id="2021" severity="info" sys="SecureNet" sub="packetfilter" name="Packet dropped" action="drop"',
    expectedHost:'SOPHOS01',
  },
);

export const SYSLOG_POC_POSITIVE=cases;

export const SYSLOG_POC_NEGATIVE:string[]=[
  '<192>Oct 16 15:44:21 BAD01 app: invalid priority',
  '<14>Foo 16 15:44:21 BAD01 app: invalid month',
  '<14>Oct 32 15:44:21 BAD01 app: invalid day',
  '<14>Oct 16 25:44:21 BAD01 app: invalid hour',
  '<14>Oct 16 15:61:21 BAD01 app: invalid minute',
  '<14>Oct 16 15:44:61 BAD01 app: invalid second',
  '<14>2026-02-30T15:44:21Z BAD01 app: invalid date',
  '<14>2026-10-16 15:44:21 +2500 BAD01 app: invalid zone',
  '<34>1 2026-02-30T15:44:21Z host app 123 ID47 - invalid rfc5424 date',
  '<34>0 2026-10-16T15:44:21Z host app 123 ID47 - invalid version',
  '<34x>Oct 16 15:44:21 host app: invalid pri token',
  'arbitrary free form prose without a syslog envelope',
];
