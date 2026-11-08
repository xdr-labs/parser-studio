import {test,expect} from '@playwright/test';
import {spawnSync} from 'node:child_process';
const raw='{"action":"allow","note":"exact source"}';
for(const vendor of ['Audit','Audit ', ' Audit', '\u00a0Audit\u00a0'])test('manufacturer whitespace preserves preview/native namespace '+JSON.stringify(vendor),async({page})=>{
 await page.addInitScript(()=>{
  const Original=window.Worker;
  (window as any).__observedSuites=[];
  (window as any).Worker=class extends Original{
   constructor(...args:any[]){super(args[0],args[1]);this.addEventListener('message',(event:any)=>{if(event.data?.suite)(window as any).__observedSuites.push(event.data.suite);});}
  };
 });
 await page.goto('/');
 await page.getByLabel('Parser manufacturer').fill(vendor);
 await page.getByLabel('Parser product',{exact:true}).fill('Namespace Audit');
 await page.getByLabel('Auto Parser raw logs').fill(raw);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const next=page.getByRole('button',{name:'Review Fields',exact:true});await expect(next).toBeEnabled({timeout:25000});await next.click();
 await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
 await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser',exact:true}).click();
 const generated=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/parser-pairs/generate'));
 await page.getByRole('button',{name:'Create Parser Files'}).click();const response=await generated;expect(response.status()).toBe(200);const pair=await response.json();
 const fragment=pair.files.find((f:any)=>!f.name.endsWith('.conf'));
 const project=JSON.parse(Buffer.from(/@parser_rule_set = JSON.parse\(Base64.strict_decode64\('([^']+)'\)\)/.exec(fragment.content)![1]!,'base64').toString('utf8'));
 const suites=await page.evaluate(()=>(window as any).__observedSuites);
 const suite=[...suites].reverse().find((s:any)=>s.events?.[0]?.normalized&&Object.keys(s.events[0].normalized).length);
 expect(suite,'Actual unmodified preview-worker output must be observed').toBeTruthy();
 expect(project.vendor).toBe('Audit');
 expect(suite.events[0].normalized.Audit?.note).toBe('exact source');
 expect(Object.hasOwn(suite.events[0].normalized,'Audit ')).toBe(false);
 // CI browser shards may not contain Ruby. The required native authoring job
 // runs the exact generated Ruby separately; run both engines here when present.
 const ruby=process.env.PARSER_RUBY_BIN||'ruby';
 if(spawnSync(ruby,['-v'],{encoding:'utf8'}).status===0){
  const program="require 'json';require 'base64';p=JSON.parse(STDIN.read);k=Class.new;k.class_eval(Base64.strict_decode64(p.fetch('ruby')).force_encoding('UTF-8'));a=k.new;r=[];a.parse(p.fetch('raw')){|t,e|r<<e};STDOUT.write(JSON.generate(r))";
  const native=spawnSync(ruby,['-e',program],{encoding:'utf8',timeout:8000,maxBuffer:1024*1024,input:JSON.stringify({ruby:Buffer.from(fragment.content).toString('base64'),raw})});
  expect(native.status,native.stderr).toBe(0);
  const record=JSON.parse(native.stdout)[0];
  const values=Object.fromEntries(Object.entries(record).filter(([k])=>!['stellar_log_index','msg_origin'].includes(k)));
  expect(values).toEqual(suite.events[0].normalized);
 }
});
