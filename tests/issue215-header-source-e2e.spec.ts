import {test,expect} from '@playwright/test';

test.skip(process.env.PARSER_STUDIO_TEST_MULTIPASS!=='1',
  'Requires the pinned isolated Python Multi-Pass service.');

const invalid=[
  '<134>Nov 32 13:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6',
  '<14>2 2026-11-05T13:00:01Z fw01 app 123 ID47 - action=deny src=192.0.2.1 dst=198.51.100.2',
];
const valid=[
  '<134>Nov  5 13:00:01 fw01 firewall: action=deny src=192.0.2.1 dst=198.51.100.2 proto=6',
  '<134>action=deny src=192.0.2.1 dst=198.51.100.2 proto=6',
];

for(const [raw,index] of [...invalid,...valid].map((raw,index)=>[raw,index] as const)){
  test('Issue #215 browser isolates malformed Syslog envelope '+index,async({page})=>{
    const errors:string[]=[];
    page.on('pageerror',error=>errors.push(error.message));
    await page.goto('/');
    await page.getByLabel('Parser manufacturer').fill('Synthetic');
    await page.getByLabel('Parser product',{exact:true}).fill('HeaderQuality');
    await page.getByLabel('Auto Parser raw logs').fill(raw);
    const reply=page.waitForResponse(response=>response.url().includes('/api/v1/multipass/preview')&&
      response.request().method()==='POST');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const response=await reply;
    expect(response.status()).toBe(200);
    const record=await response.json() as {status?:string;events?:Array<{preview:{status:string}}>;error?:string};
    expect(record.error).toBeUndefined();
    const status=record.events?.[0]?.preview.status??record.status;
    if(index<invalid.length){
      expect(['PARTIAL','RAW_ONLY']).toContain(status);
      await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
    }else{
      expect(status).toBe('SOURCE_PARSED');
      // The browser's independent authoring policy may intentionally require
      // review for PRI-only vendor envelopes despite API source completeness.
      if(index===invalid.length)
        await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
    }
    expect(errors).toEqual([]);
  });
}
