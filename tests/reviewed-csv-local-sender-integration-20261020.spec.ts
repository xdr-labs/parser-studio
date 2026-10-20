import {expect,test} from '@playwright/test';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('./fixtures/reviewed-pair-sender-20261020.csv',import.meta.url),'utf8').trimEnd();

test('reviewed two-column CSV survives local restore and downloaded Python transformation',async({page})=>{
  test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
    'Requires the exact-HEAD localhost authoring backend and Python Multi-Pass.');
  test.setTimeout(90_000);
  const pageErrors:string[]=[];
  const httpFailures:number[]=[];
  const externalRequests:string[]=[];
  page.on('pageerror',error=>pageErrors.push(error.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)httpFailures.push(response.status());
  });
  await page.goto('/');
  const origin=new URL(page.url()).origin;
  page.on('request',request=>{
    if(/^https?:/.test(request.url())&&new URL(request.url()).origin!==origin)
      externalRequests.push(request.url());
  });
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(source);
  await expect(page.getByLabel('Automatic event accounting')).toContainText('2/2 events checked');
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const csv=page.getByLabel('Review CSV column names');
  await expect(csv).toContainText('2 consistent columns detected');
  await csv.getByLabel('Reviewed CSV column names').fill('action,url');
  await csv.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();

  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await history.getByLabel('Local version name').fill('Reviewed pair');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history.getByLabel('Saved local versions')).toContainText('Reviewed pair');
  await input.fill('{"action":"different experiment"}');
  page.on('dialog',dialog=>dialog.accept());
  await history.getByText('Reviewed pair',{exact:true}).locator('..').locator('..')
    .getByRole('button',{name:'Restore',exact:true}).click();
  await expect(input).toHaveValue(source);

  const sender=page.getByRole('group',{name:'Python test sender'});
  await sender.locator('summary').click();
  const requested=page.waitForEvent('download');
  await sender.getByRole('button',{name:'Download Python Test Sender'}).click();
  const downloaded=await requested;
  expect(downloaded.suggestedFilename()).toBe('parser_studio_test_sender.py');
  await expect(sender.getByRole('status')).toContainText('No log was transmitted by Parser Studio.');
  const file=await downloaded.path();
  expect(file).toBeTruthy();

  // Exercise only the downloaded pure transform. The audit hook rejects even
  // an attempted socket operation; main() and destination prompts never run.
  const program=[
    'import csv,io,json,runpy,sys',
    'def audit(event,args):',
    '    if event.startswith("socket."): raise RuntimeError("Network is forbidden in this offline test")',
    'sys.addaudithook(audit)',
    'scope=runpy.run_path(sys.argv[1])',
    'config=scope["_payload"]()',
    'mutated=[scope["update_record"](row,config) for row in config["events"]]',
    'rows=[next(csv.reader(io.StringIO(row),delimiter=config["csv_delimiter"],strict=True)) for row in mutated]',
    'print(json.dumps({"config":config,"mutated":mutated,"rows":rows}))',
  ].join('\n');
  const result=JSON.parse(execFileSync('python3',['-c',program,file!],{
    encoding:'utf8',timeout:5000,maxBuffer:200000,
  })) as {config:Record<string,unknown>;mutated:string[];rows:string[][]};
  expect(result.config).toMatchObject({
    events:source.split('\n'),format:'csv',csv_columns:['action','url'],csv_delimiter:',',event_boundary:'single-line',
  });
  expect(result.rows).toHaveLength(2);
  const originals=source.split('\n');
  for(let i=0;i<result.rows.length;i++){
    expect(result.rows[i]).toHaveLength(2);
    expect(result.mutated[i]).toMatch(/^"[^"]+","[^"]+"$/);
    expect(result.rows[i][0]).toBe(originals[i].split('","')[0].slice(1));
    const before=new URL(originals[i].split('","')[1].slice(0,-1));
    const after=new URL(result.rows[i][1]);
    expect([...after.searchParams.keys()]).toEqual(['user','srcip']);
    expect(after.searchParams.get('user')).toBe(before.searchParams.get('user'));
    expect(after.searchParams.get('srcip')).not.toBe(before.searchParams.get('srcip'));
  }
  await expect(input).toHaveValue(source);
  expect(pageErrors).toEqual([]);expect(httpFailures).toEqual([]);expect(externalRequests).toEqual([]);
});
