import {test,expect} from '@playwright/test';
// All inputs authored for protocol behavior testing, not original customer logs.
const msg='<134>1 2026-10-19T08:05:00Z host demo 42 evt - action=deny user="김민수"';
const json='{"event_type":"alert","src_ip":"192.0.2.1","username":"김민수"}';
const examples=[
 {id:'RFC6587 octet UTF8',raw:(Buffer.byteLength(msg,'utf8')+' '+msg).repeat(2),n:2},
 {id:'RFC6587 NUL',raw:msg+'\0'+msg+'\0',n:2},
 {id:'RFC7464 JSON sequence',raw:'\x1e'+json+'\n\x1e'+json+'\n',n:2},
 {id:'GELF TCP',raw:'{"version":"1.1","host":"host","short_message":"blocked","level":3}\0',n:1},
 {id:'Journal grouped',raw:'MESSAGE=action=deny src=192.0.2.1\nPRIORITY=5\n\nMESSAGE=action=allow src=192.0.2.2\nPRIORITY=6\n',n:2},
];
for(const item of examples){
 test(item.id+' shows original-source frame review',async({page})=>{
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  const resps:any[]=[];
  page.on('response',async r=>{if(r.url().endsWith('/api/v1/multipass/preview-batch')&&r.ok())resps.push(await r.json());});
  await page.goto('/');
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(item.raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect.poll(()=>resps.length,{timeout:18000}).toBe(1);
  const body=resps[0];
  expect(body.eventCount).toBe(item.n);
  expect(body.events.every((e:any)=>e.preview.status==='PARTIAL')).toBeTruthy();
  expect(body.events.every((e:any)=>e.preview.nativeVerified===false)).toBeTruthy();
  expect(body.separators.some((s:any)=>s.kind==='SOURCE_FRAMING')).toBeTruthy();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible();
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  await expect(source).toHaveValue(item.raw);
  expect(errors).toEqual([]);
 });
}
