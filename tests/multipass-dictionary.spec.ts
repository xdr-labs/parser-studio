import {test,expect} from '@playwright/test';

test('Stellar 7.0 field mapping keeps unknown vendor values and requires no advanced analysis UI',async({page})=>{
  const raw='srcip=192.0.2.10 dstport=443 action=deny custom=PRIVATE_VALUE';
  const sent:string[]=[];
  page.on('request',req=>{
    if(req.method()==='POST'){
      const path=new URL(req.url()).pathname;
      if(path.startsWith('/api/v1/parser-pairs/')){
        sent.push(path);
        expect(req.postData()??'').not.toContain('PRIVATE_VALUE');
      }
    }
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  await expect(page.getByLabel('Browser-only event inspector')).toContainText('PRIVATE_VALUE');
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toContainText('Stellar field dictionary 7.0.xs');
  const sources=map.locator('input[aria-label^="Source field "]');
  const actual=await sources.evaluateAll(nodes=>nodes.map((node,index)=>({
    source:(node as HTMLInputElement).value,index,
  })));
  for(const name of ['srcip','dstport','action']){
    const row=actual.find(item=>item.source===name);
    expect(row,'source field '+name).toBeTruthy();
    await expect(map.getByLabel('Stellar field '+row!.index,{exact:true})).toHaveValue(name);
  }
  const unknown=actual.find(item=>item.source==='custom');
  expect(unknown).toBeTruthy();
  expect(await map.getByLabel('Stellar field '+unknown!.index,{exact:true}).inputValue()).not.toBe('srcip');
  expect(sent).toEqual([]);
  await expect(page.getByLabel('Deeper local log analysis',{exact:true})).toHaveCount(0);
});
