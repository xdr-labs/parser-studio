import {test,expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
const cases=[
 {name:'FortiGate device identity',vendor:'Fortinet',product:'FortiGate',field:'devname',prior:'devname',target:'device_hostname',
  raw:'date=2026-10-23 time=12:11:13 devname="FW01" type=traffic srcip=192.0.2.11 dstip=198.51.100.11 action=deny service=HTTPS',
  holdout:['date=2026-10-23 time=12:11:14 devname="FW02" type=traffic srcip=192.0.2.12 dstip=198.51.100.12 action=allow service=HTTPS','date=2026-10-23 time=12:11:15 devname="FW03" type=traffic srcip=192.0.2.13 dstip=198.51.100.13 action=deny service=HTTP'].join('\n')},
 {name:'Suricata alert signature',vendor:'OISF',product:'Suricata EVE',field:'alert.signature',prior:'signature',target:'attack_signature_reviewed',
  raw:JSON.stringify({timestamp:'2026-10-23T12:11:13Z',event_type:'alert',src_ip:'192.0.2.11',dest_ip:'198.51.100.11',alert:{signature_id:1001,signature:'Synthetic test rule',severity:2}}),
  holdout:[JSON.stringify({timestamp:'2026-10-23T12:11:14Z',event_type:'alert',src_ip:'192.0.2.12',dest_ip:'198.51.100.12',alert:{signature_id:1002,signature:'Second test rule',severity:1}}),JSON.stringify({timestamp:'2026-10-23T12:11:15Z',event_type:'alert',src_ip:'192.0.2.13',dest_ip:'198.51.100.13',alert:{signature_id:1003,signature:'Third test rule',severity:2}})].join('\n')},
 {name:'CloudTrail API operation',vendor:'Amazon',product:'CloudTrail',field:'eventName',prior:'eventName',target:'api_operation',
  raw:JSON.stringify({eventTime:'2026-10-23T12:11:13Z',eventSource:'iam.amazonaws.com',eventName:'CreateUser',sourceIPAddress:'192.0.2.11',userIdentity:{userName:'testuser'}}),
  holdout:[JSON.stringify({eventTime:'2026-10-23T12:11:14Z',eventSource:'iam.amazonaws.com',eventName:'DeleteUser',sourceIPAddress:'192.0.2.12',userIdentity:{userName:'testuser2'}}),JSON.stringify({eventTime:'2026-10-23T12:11:15Z',eventSource:'iam.amazonaws.com',eventName:'UpdateUser',sourceIPAddress:'192.0.2.13',userIdentity:{userName:'testuser3'}})].join('\n')}
];
const B='----- BEGIN VALIDATED BASELINE RECIPE -----\n',E='\n----- END VALIDATED BASELINE RECIPE -----';
for(const item of cases){
 test('controlled vendor mapping correction, real prompt, real compiler: '+item.name,async({page})=>{
  const errs:string[]=[];page.on('pageerror',e=>errs.push(e.message));
  await page.goto('/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(item.raw);
  await page.getByLabel('Parser manufacturer').fill(item.vendor);
  await page.getByLabel('Parser product',{exact:true}).fill(item.product);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=page.getByLabel('ChatGPT copyable prompt');await expect(prompt).toBeVisible({timeout:20000});
  const text=await prompt.inputValue(),l=text.indexOf(B),r=text.indexOf(E,l+B.length);
  expect(l).toBeGreaterThanOrEqual(0);expect(r).toBeGreaterThan(l);
  const proposal=JSON.parse(text.slice(l+B.length,r));
  const map=proposal.stages.find((s:any)=>s.op==='map_field'&&s.source===item.field);
  expect(map).toBeTruthy();expect(map.target).toBe(item.prior);
  map.target=item.target;
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(proposal));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  await expect(page.getByLabel('ChatGPT result ready for testing')).toContainText('accepted for testing',{timeout:15000});
  const apply=page.getByRole('button',{name:'Apply Fix & Create Parser Files'});
  await expect(apply).toBeDisabled();
  await page.getByLabel('Additional ChatGPT test logs').fill(item.holdout);
  await page.getByLabel('Confirm test examples are different').check();
  await page.getByRole('button',{name:'Test Proposed Fix'}).click();
  const result=page.getByLabel('ChatGPT fix test result');
  await expect(result).toContainText('Original logs still pass: YES',{timeout:30000});
  await expect(result).toContainText('Additional logs tested: YES');
  await expect(result).toContainText('Overall test: PASS');
  // A good independent comparison alone must not apply an AI edit.
  await expect(apply).toBeDisabled();
  await page.getByLabel('Approve tested ChatGPT fix').check();
  await apply.click();
  const download=page.getByLabel('ChatGPT created parser files');
  await expect(download).toContainText('Parser files created successfully',{timeout:30000});
  const fileEvent=page.waitForEvent('download');
  await download.getByRole('button',{name:/Download .*\.conf$/}).click();
  const file=await fileEvent;
  expect((await readFile(await file.path(),'utf8'))).toContain('port 6801');
  expect(errs).toEqual([]);
  console.log('VENDOR_MAPPING_REVIEW '+JSON.stringify({name:item.name,sourceField:item.field,sourceTarget:item.prior,proposalTarget:item.target,changed:true,holdoutPassed:true,approved:true,downloaded:file.suggestedFilename()}));
 });
}
