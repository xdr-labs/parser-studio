import {test,expect} from '@playwright/test';
const rows=(n:number)=>Array.from({length:n},(_,i)=>JSON.stringify({
 timestamp:'2026-10-23T10:00:00Z',
 event_type:['threat','user','asset'][i%3],
 src_ip:'192.0.2.'+(i%250+1),port:i%2?443:80,
 action:i%2?'deny':'allow',id:'test-'+i
})).join('\n');

test('500 valid JSON events preserve every source event and remain reviewable',async({page})=>{
 const error:string[]=[];
 page.on('pageerror',e=>error.push(e.message));
 await page.goto('/');
 const data=rows(500),input=page.getByLabel('Auto Parser raw logs');
 expect(Buffer.byteLength(data,'utf8')).toBeLessThan(65536);
 await input.fill(data);
 await expect(page.getByLabel('Automatic event accounting')).toContainText('500/500 events',{timeout:25000});
 await expect(page.getByLabel('Auto Parser sample limit')).toHaveCount(0);
 await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
 const summary=page.getByLabel('Beginner analysis summary');
 await expect(summary).toBeVisible({timeout:40000});
 const headline=await summary.locator('.beginner-analysis-head strong').first().innerText();
 await expect(input).toHaveValue(data);
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled({timeout:25000});
 await page.getByRole('button',{name:'Review Fields',exact:true}).click();
 await expect(page.getByLabel('Review Fields stage')).toBeVisible();
 const result={events:500,sourceBytes:Buffer.byteLength(data,'utf8'),headline,pageErrors:error};
 console.log('BOUNDARY_MATRIX '+JSON.stringify(result));
 expect(error).toEqual([]);
});

test('501 source events are not silently truncated or sent for parser generation',async({page})=>{
 const error:string[]=[];let generated=0;
 page.on('pageerror',e=>error.push(e.message));
 page.on('request',r=>{if(r.method()==='POST'&&r.url().includes('/parser-pairs/generate'))generated++;});
 await page.goto('/');
 const data=rows(501),input=page.getByLabel('Auto Parser raw logs');
 expect(Buffer.byteLength(data,'utf8')).toBeLessThan(65536);
 await input.fill(data);
 const warning=page.getByLabel('Auto Parser sample limit');
 await expect(warning).toContainText('Use at most 500 logical events and 64 KiB');
 await expect(warning).toContainText('will not silently drop the extra events');
 await expect(page.getByLabel('Automatic event accounting')).toContainText('0/501 events');
 await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
 await expect(input).toHaveValue(data);
 const result={events:501,sourceBytes:Buffer.byteLength(data,'utf8'),limitShown:true,generated,pageErrors:error};
 console.log('BOUNDARY_MATRIX '+JSON.stringify(result));
 expect(generated).toBe(0);expect(error).toEqual([]);
});
