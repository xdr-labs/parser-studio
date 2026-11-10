import {test,expect} from './support/downloadSink';
import {execFileSync} from 'node:child_process';

const source='allow,gw01,https://example.test/path?user=alice&srcip=192.0.2.10';

test('downloaded auto Python test sender preserves all positional CSV URL query parameters offline',async({page})=>{
  const apiWrites:string[]=[];
  const pageErrors:string[]=[];
  page.on('request',request=>{
    if(request.url().includes('/api/')&&request.method()!=='GET')
      apiWrites.push(request.url());
  });
  page.on('pageerror',error=>pageErrors.push(error.message));
  await page.goto('/');
  const input=page.getByLabel('Auto Parser raw logs');
  await input.fill(source);
  const panel=page.getByRole('group',{name:'Python test sender'});
  await panel.locator('summary').click();
  const requested=page.waitForEvent('download');
  await panel.getByRole('button',{name:'Download Python Test Sender'}).click();
  const downloaded=await requested;
  expect(downloaded.suggestedFilename()).toBe('parser_studio_test_sender.py');
  await expect(panel.getByRole('status')).toContainText('No log was transmitted by Parser Studio.');
  const file=await downloaded.path();
  expect(file).toBeTruthy();

  // The downloaded Python is loaded but main() is never called. No socket,
  // destination, sensor or data transfer is involved in this offline check.
  const script=[
    'import json,runpy,sys',
    'scope=runpy.run_path(sys.argv[1])',
    'config=scope["_payload"]()',
    'original=config["events"][0]',
    'actual=scope["update_record"](original,config)',
    'print(json.dumps({"format":config["format"],"original":original,"mutated":actual}))',
  ].join('\n');
  const output=execFileSync('python3',['-c',script,file!],{
    encoding:'utf8',timeout:5000,maxBuffer:200000,
  });
  const result=JSON.parse(output) as {format:string;original:string;mutated:string};
  expect(result.format).toBe('auto');
  expect(result.original).toBe(source);
  const columns=result.mutated.split(',');
  expect(columns).toHaveLength(3);
  expect(result.mutated).toContain('?user=alice&srcip=');
  const query=new URL(columns[2]!).searchParams;
  expect(query.get('user')).toBe('alice');
  // Compare the complete URL parameter: a valid mutation such as
  // 192.0.2.107 still contains 192.0.2.10 as a text prefix.
  expect(query.get('srcip')).toMatch(/^(?:\d{1,3}\.){3}\d{1,3}$/);
  expect(query.get('srcip')).not.toBe('192.0.2.10');
  expect(apiWrites).toEqual([]);
  expect(pageErrors).toEqual([]);
});
