import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

const sample=readFileSync(resolve('tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8').trimEnd();

test.skip(process.env.PARSER_STUDIO_BROWSER_BACKEND!=='1'||
          process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
          'Run against pinned candidate backend and locally built frontend.');
test('Issue #232 original tutorial: shared numeric port aliases compile to DRAFT pair',
  async({page})=>{
    test.setTimeout(90000);
    const jsErrors:string[]=[],apiErrors:string[]=[];
    page.on('pageerror',e=>jsErrors.push(e.message));
    page.on('response',r=>{
      if(r.url().includes('/api/')&&r.status()>=500)apiErrors.push(r.url()+' '+r.status());
    });
    await page.goto('/');
    await page.getByLabel('Parser manufacturer').fill('Juniper');
    await page.getByLabel('Parser product',{exact:true}).fill('SRX');
    await page.getByLabel('Auto Parser raw logs').fill(sample);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const review=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(review).toBeEnabled({timeout:30000});
    await review.click();
    await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
    const stage=page.getByLabel('Map Fields stage');
    await expect(stage.getByLabel('Field mapping summary')).toContainText('Matched to Stellar8');
    await expect(stage.getByLabel('Protocol-aware mapping explanation')).toHaveCount(0);
    await expect(stage.getByText(/Conditional official field:/)).toHaveCount(0);
    const rows=await stage.locator('article.normalization-map-row').evaluateAll(nodes=>nodes.map(node=>({
      source:(node.querySelector('input[aria-label^="Source field "]') as HTMLInputElement|null)?.value??'',
      target:(node.querySelector('input[aria-label^="Stellar field "],input[aria-label^="Vendor field "]') as HTMLInputElement|null)?.value??'',
      official:node.classList.contains('verified'),vendor:node.classList.contains('custom'),
    })));
    const prefix='syslog_sd.element_1.params.';
    for(const [source,target] of [['source-port','srcport'],['destination-port','dstport']] as const){
      expect(rows.filter(row=>row.source===prefix+source)).toEqual([
        expect.objectContaining({source:prefix+source,target,official:true,vendor:false}),
      ]);
    }
    await expect(stage.getByLabel('Field mapping summary')).toContainText('Must fix before continuing0');
    await stage.getByRole('button',{name:'Create Parser',exact:true}).click();
    await expect(page.getByLabel('Create Parser stage')).toBeVisible();
    const response=page.waitForResponse(r=>r.url().endsWith('/parser-pairs/generate')&&
      r.request().method()==='POST',{timeout:45000});
    await page.getByRole('button',{name:'Create Parser Files'}).click();
    const result=await response;
    expect(result.status()).toBe(200);
    const pair=await result.json() as {manifest:{status:string;engineVerified:boolean;targetImportVerified:boolean},files:Array<{name:string;content:string}>};
    expect(pair.manifest).toMatchObject({status:'DRAFT',engineVerified:false,targetImportVerified:false});
    expect(pair.files).toHaveLength(2);
    expect(pair.files.map(f=>f.name)).toEqual(expect.arrayContaining(['customized_juniper_srx.conf','customized_juniper_srx']));
    const ruby=pair.files.find(f=>!f.name.endsWith('.conf'))?.content??'';
    const embedded=ruby.match(/@parser_rule_set = JSON\.parse\(Base64\.strict_decode64\('([^']+)'\)\)/)?.[1];
    expect(embedded).toBeTruthy();
    const project=JSON.parse(Buffer.from(embedded!,'base64').toString('utf8')) as {
      normalization:{topFields:Record<string,{normalized_name:string;data_type:string}>;
        vendorFields:Record<string,unknown>};
    };
    expect(project.normalization.topFields[prefix+'source-port']).toMatchObject({
      normalized_name:'srcport',data_type:'integer',
    });
    expect(project.normalization.topFields[prefix+'destination-port']).toMatchObject({
      normalized_name:'dstport',data_type:'integer',
    });
    expect(project.normalization.vendorFields[prefix+'source-port']).toBeUndefined();
    expect(project.normalization.vendorFields[prefix+'destination-port']).toBeUndefined();
    await expect(page.getByLabel('Generated parser files')).toBeVisible();
    expect(jsErrors).toEqual([]);
    expect(apiErrors).toEqual([]);
  });
