import {test,expect,type Page} from '@playwright/test';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
  'Run only with the exact candidate source, authoring backend and isolated Multi-Pass.');

const slash=String.fromCharCode(92);
const windowsPath='C:'+slash+'Windows'+slash+'System32'+slash+'cmd.exe';

async function submit(page:Page,raw:string){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByLabel('Parser manufacturer').fill('Audit Vendor');
  await page.getByLabel('Parser product',{exact:true}).fill('Security Gateway');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
}
async function generate(page:Page){
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  const mapping=page.getByLabel('Field mapping summary');
  await expect(mapping).toContainText('Must fix before continuing');
  await expect(mapping).toContainText(/Must fix before continuing\s*0/);
  await page.getByRole('button',{name:'Create Parser',exact:true}).click();
  const create=page.getByRole('button',{name:'Create Parser Files',exact:true});
  await expect(create).toBeEnabled({timeout:15000});
  const network=page.waitForResponse(reply=>
    new URL(reply.url()).pathname==='/api/v1/parser-pairs/generate'&&
    reply.request().method()==='POST',{timeout:25000});
  await create.click();
  const response=await network;
  expect(response.status()).toBe(200);
  const body=await response.json();
  expect(body.manifest?.status).toBe('DRAFT');
  expect(body.files).toHaveLength(2);
  for(const file of body.files){
    expect(file.sha256).toBe(createHash('sha256').update(file.content).digest('hex'));
  }
  const ruby=body.files.find((file:{name:string})=>!file.name.endsWith('.conf'));
  expect(ruby).toBeDefined();
  await expect(page.getByLabel('Generated parser files')).toBeVisible();
  return ruby.content as string;
}
function runRuby(source:string,raw:string){
  const code=[
    "require 'json'","require 'base64'","require 'ipaddr'","require 'time'","require 'csv'",
    'input=JSON.parse(STDIN.read)',
    'klass=Class.new',
    "klass.class_eval(Base64.strict_decode64(input.fetch('ruby')),'generated_browser_audit',1)",
    'parser=klass.new',
    'record=nil',
    "parser.parse(input.fetch('raw')){|_time,event|record=event}",
    'STDOUT.write(JSON.generate(record))',
  ].join('\n');
  const result=spawnSync(process.env.PARSER_RUBY_BIN||'ruby',['-e',code],{
    encoding:'utf8',input:JSON.stringify({ruby:Buffer.from(source).toString('base64'),raw}),
    maxBuffer:1024*1024,timeout:15000,
  });
  expect(result.status,result.stderr||String(result.error)).toBe(0);
  return JSON.parse(result.stdout) as Record<string,unknown>;
}
function allValues(input:unknown):unknown[]{
  if(Array.isArray(input))return input.flatMap(allValues);
  if(input&&typeof input==='object')return Object.values(input).flatMap(allValues);
  return [input];
}

test('novice KV creation keeps the literal original Windows path in generated Ruby output',async({page})=>{
  test.setTimeout(85000);
  const raw='action=deny src_ip=192.0.2.10 path="'+windowsPath+'"';
  await submit(page,raw);
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('1 of 1 log event structurally parsed');
  const ruby=await generate(page);
  const result=runRuby(ruby,raw);
  expect(result).not.toHaveProperty('parser_err_msg');
  expect(allValues(result)).toContain(windowsPath);
  expect(allValues(result)).not.toContain('C:WindowsSystem32cmd.exe');
});
test('novice whitespace-padded port is accepted by the generated Ruby parser',async({page})=>{
  test.setTimeout(85000);
  const raw='action=deny src_ip=192.0.2.10 dst_port=" 443 "';
  await submit(page,raw);
  const ruby=await generate(page);
  const result=runRuby(ruby,raw);
  expect(result).not.toHaveProperty('parser_err_msg');
  expect(allValues(result)).toContain(443);
});
test('unsafe JSON 64-bit numeric session IDs cannot be approved as complete DRAFTs',async({page})=>{
  test.setTimeout(85000);
  const raw='{"action":"deny","src_ip":"192.0.2.10","session_id":9007199254740993}';
  await submit(page,raw);
  const next=page.getByRole('button',{name:'Review Fields',exact:true});
  if(await next.isEnabled()){
    await next.click();
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    const mapping=page.getByRole('button',{name:'Map Fields',exact:true});
    if(await mapping.isEnabled()){
      await mapping.click();
      const create=page.getByRole('button',{name:'Create Parser',exact:true});
      await expect(create).toBeDisabled();
    }
  }
  await expect(page.getByLabel('Generated parser files')).toHaveCount(0);
});
