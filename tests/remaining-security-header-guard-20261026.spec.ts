import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
const origin='https://app.parser.xdr.ooo';
test.skip(process.env.PARSER_STUDIO_PUBLIC_NOVICE_CROSS_E2E!=='1',
 'Explicit operator-only public Chromium check, never part of default CI.');
const cases=[
 {id:'Zeek declared tab schema with original header',vendor:'Zeek',product:'Zeek conn',
  raw:'#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n1760832000.000\tCw01\t192.0.2.10\t198.51.100.3\ttcp\n1760832001.000\tCw02\t192.0.2.11\t198.51.100.4\tudp',
  hold:'#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\n1760832002.000\tCw03\t192.0.2.12\t198.51.100.5\ttcp\n1760832003.000\tCw04\t192.0.2.13\t198.51.100.6\tudp',
  delimiter:'\t' as const,columns:['ts','uid','orig_h','resp_h','proto']},
 {id:'W3C IIS declared space-separated schema',vendor:'Microsoft',product:'IIS W3C',
  raw:'#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-19 08:44:01 192.0.2.10 GET /login 403',
  hold:'#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-20 08:44:02 192.0.2.11 POST /submit 401\n2026-10-20 08:44:03 192.0.2.12 GET /health 200',
  delimiter:'\t' as const,columns:['date','time','cip','method','path','code']}
];
for(const c of cases){
 test('header-aware source cannot silently become unsupported v0.2 parser: '+c.id,async({page})=>{
  const errors:string[]=[],backend5xx:number[]=[],outside:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('response',r=>{if(r.url().includes('/api/')&&r.status()>=500)backend5xx.push(r.status())});
  page.on('request',r=>{try{const u=new URL(r.url());if(/^https?:$/.test(u.protocol)&&u.origin!==origin)outside.push(u.origin)}catch{}});
  await page.goto(origin+'/');
  await page.getByLabel('Auto Parser raw logs').fill(c.raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
  await expect(page.getByLabel('Parse problem inspector')).toBeVisible();
  await page.goto(origin+'/?workspace=chatgpt');
  await page.getByLabel('ChatGPT local sample logs').fill(c.raw);
  await page.getByLabel('ChatGPT solution vendor').fill(c.vendor);
  await page.getByLabel('ChatGPT solution product').fill(c.product);
  await page.getByRole('button',{name:'Prepare ChatGPT Prompt'}).click();
  const prompt=await page.getByLabel('ChatGPT copyable prompt').inputValue();
  expect(prompt).toContain(c.raw);
  expect(prompt).toContain(sha(c.raw));
  const m=prompt.match(/"projectId":"(draft-[a-z][a-z0-9_]+)","sourceHash":"([a-f0-9]{64})","sourceCount":(\d+)/);
  expect(m?.[2]).toBe(sha(c.raw));
  const stages:Array<Record<string,unknown>>=[
   {op:'split_event',boundary:'single-line'},
   {op:'parse_csv',columns:c.columns,delimiter:c.delimiter},
   ...c.columns.map(name=>({op:'map_field',source:name,target:name,data_type:'string',group:'vendor_fields'})),
   {op:'classify',defaultIndex:'syslog',rules:[]},
   {op:'fallback_unparsed',mode:'retain_unparsed'}
  ];
  const response={
   contract:'parser-studio.recipe.v0.2',schemaRevision:'0.2',compilerMode:'REVIEW_ONLY',
   projectId:m![1],sourceFormat:'csv',bodyFormat:'csv',
   sample:{sha256:sha(c.raw),events:Number(m![3])},stages,nativeVerified:false,targetVerified:false
  };
  await page.getByLabel('ChatGPT result JSON').fill(JSON.stringify(response));
  await page.getByRole('button',{name:'Check ChatGPT Result'}).click();
  const accepted=page.getByLabel('ChatGPT result ready for testing');
  const rejected=page.getByRole('status').filter({hasText:'ChatGPT result rejected'});
  await expect(accepted.or(rejected)).toBeVisible({timeout:15000});
  let disposition='RECIPE_REJECTED';
  if(await accepted.isVisible()){
   await page.getByLabel('Additional ChatGPT test logs').fill(c.hold);
   await page.getByLabel('Confirm test examples are different').check();
   await page.getByRole('button',{name:'Test Proposed Fix'}).click();
   const report=page.getByLabel('ChatGPT fix test result');
   await expect(report).toBeVisible({timeout:25000});
   const detail=await report.innerText();
   disposition=detail.includes('Overall test: PASS')?'UNEXPECTED_PASS':'REVIEW_REQUIRED';
   console.log('HEADER_COMPARE '+JSON.stringify({id:c.id,result:detail.slice(0,450)}));
   expect(disposition).toBe('REVIEW_REQUIRED');
   await expect(page.getByRole('button',{name:'Apply Fix & Create Parser Files'})).toBeDisabled();
  }
  await expect(page.getByLabel('ChatGPT created parser files')).toHaveCount(0);
  expect(errors).toEqual([]);expect(backend5xx).toEqual([]);expect(outside).toEqual([]);
  console.log('HEADER_GUARD '+JSON.stringify({id:c.id,sha256:sha(c.raw),disposition,noParserGenerated:true,modelCompletions:0}));
 });
}
