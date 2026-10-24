import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const fortigate=[
 'date=2026-10-24 time=11:00:00 type="traffic" subtype="forward" action="accept" srcip=192.0.2.10 dstip=198.51.100.5',
 'date=2026-10-24 time=11:00:01 type="utm" subtype="ips" eventtype="signature" action="dropped" srcip=192.0.2.11 dstip=198.51.100.6',
 'date=2026-10-24 time=11:00:02 type="utm" subtype="virus" eventtype="infected" action="blocked" srcip=192.0.2.12 dstip=198.51.100.7',
 'date=2026-10-24 time=11:00:03 type="event" subtype="vpn" action="tunnel-up" user="testuser"',
].join('\n');
const suricata=['alert','http','dns','flow'].map((event_type,i)=>JSON.stringify({
 timestamp:'2026-10-24T12:00:00Z',event_type,src_ip:'192.0.2.'+(20+i),
 dest_ip:'198.51.100.'+(20+i),proto:'TCP',
})).join('\n');
function own(source:string){
 return createHash('sha256').update(source,'utf8').digest('hex');
}
for(const item of [
 {name:'FortiGate firewall/IPS/AV/VPN',source:fortigate,expected:['type=traffic subtype=forward',
   'type=utm subtype=ips','type=utm subtype=virus','type=event subtype=vpn']},
 {name:'Suricata alert/http/dns/flow',source:suricata,expected:['event_type=alert',
   'event_type=http','event_type=dns','event_type=flow']},
]){
 test('security product multi-event prompt includes original type coverage without inventing event mappings: '+item.name,async({page,context})=>{
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  const errors:string[]=[],outside:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/?workspace=chatgpt');
  const base=new URL(page.url()).origin;
  page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(base+'/'))outside.push(r.url());});
  await page.getByLabel('ChatGPT local sample logs').fill(item.source);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const input=page.getByLabel('ChatGPT copyable prompt');
  await expect(input).toBeVisible({timeout:18000});
  const prompt=await input.inputValue();
  const hash=own(item.source),m=prompt.match(/\{"projectId":"([^"]+)","sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)\}/);
  expect(m).toBeTruthy();
  expect(m![2]).toBe(hash);
  expect(Number(m![3])).toBe(4);
  const begin='----- BEGIN ORIGINAL LOG SOURCE ['+hash.slice(0,20)+'] -----\n';
  const end='\n----- END ORIGINAL LOG SOURCE ['+hash.slice(0,20)+'] -----';
  expect(prompt.split(begin)[1]?.split(end)[0]).toBe(item.source);
  expect(prompt).toContain('Observed event-type diversity in the EXACT original source');
  for(const selector of item.expected)expect(prompt).toContain(selector);
  expect(prompt).toContain('Cover EVERY distinct observed kind');
  expect(prompt).toContain('without overwriting existing extractions');
  await page.getByRole('button',{name:'Copy Prompt'}).click();
  const copied=await page.evaluate(()=>navigator.clipboard.readText());
  expect(copied).toBe(prompt);
  expect(errors).toEqual([]);
  expect(outside).toEqual([]);
 });
}
test('one security event type cannot claim multi-type product coverage',async({page})=>{
 const single='type="utm" subtype="ips" eventtype="signature" action="blocked" srcip=192.0.2.31';
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill(single);
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const input=page.getByLabel('ChatGPT copyable prompt');
 await expect(input).toBeVisible({timeout:16000});
 const prompt=await input.inputValue();
 expect(prompt).toContain('Only 1 distinct explicit event selector(s)');
 expect(prompt).toContain('Do not fabricate missing examples');
 expect(prompt).not.toContain('type=utm subtype=virus');
});
test('security log baseline fields remain explicitly protected without echoing source values in notes',async({page})=>{
 const raw=[
  '{"event_type":"alert","action":"deny","src_ip":"192.0.2.51"}',
  '{"event_type":"flow","action":"allow","src_ip":"192.0.2.52"}',
 ].join('\n');
 await page.goto('/?workspace=chatgpt');
 await page.getByLabel('ChatGPT local sample logs').fill(raw);
 await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
 const input=page.getByLabel('ChatGPT copyable prompt');
 await expect(input).toBeVisible({timeout:17000});
 const prompt=await input.inputValue();
 expect(prompt).toContain('Source field paths ALREADY extracted by local preview');
 expect(prompt).toContain('"sourcePath":"src_ip"');
 expect(prompt).toContain('"sourcePath":"action"');
 expect(prompt).toContain('Do not replace a previously extracted value');
 const before=prompt.split('The ORIGINAL log source begins')[0]!;
 expect(before).not.toContain('192.0.2.51');
 expect(before).not.toContain('192.0.2.52');
});
