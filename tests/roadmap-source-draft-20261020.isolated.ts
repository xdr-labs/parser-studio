import {test,expect,type Page,type TestInfo} from '@playwright/test';
import {writeFile} from 'node:fs/promises';

const fixtures={
  rfc5424:'<134>1 2026-10-19T09:15:22.123Z fw01 application 12 audit [meta@12345 action="deny" src="192.0.2.10"] firewall denied',
  prefixedKv:'<134>Oct 19 08:23:59 ftd01 %FTD-4-430002: Intrusion event detected signature=1000123 src=192.0.2.40 dst=198.51.100.5 action=block',
  implicitTabLeef:'LEEF:2.0|Zscaler|NSS|1.0|web-block|\tusrName=alice\tsrc=192.0.2.6\tdst=198.51.100.4\turl=https://example.test/login\taction=blocked',
};

async function analyze(page:Page,raw:string){
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
}

async function downloadDraft(page:Page,info:TestInfo,raw:string,format:string){
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:20000});
  await review.click();
  const fields=page.getByLabel('Review Fields stage');
  await expect(fields).toBeVisible({timeout:20000});
  await fields.getByRole('button',{name:'Map Fields',exact:true}).click();
  const mapping=page.getByLabel('Map Fields stage');
  await expect(mapping.getByLabel('Field mapping checks')).toContainText('No mapping problems found');
  await mapping.getByRole('button',{name:'Create Parser',exact:true}).click();
  await page.getByLabel('Create Parser Files').click();
  const generated=page.getByLabel('Generated parser files');
  await expect(generated).toContainText('Parser files created successfully',{timeout:30000});
  await expect(generated).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  const contents:Record<string,string>={};
  for(const suffix of ['customized_demo_firewall','customized_demo_firewall.conf']){
    const pending=page.waitForEvent('download');
    await generated.getByRole('button',{name:new RegExp(suffix.replaceAll('.','\\.')+'$')}).click();
    const artifact=await pending;
    expect(artifact.suggestedFilename()).toBe(suffix);
    const chunks:Buffer[]=[];
    for await(const chunk of (await artifact.createReadStream())!)chunks.push(Buffer.from(chunk));
    contents[suffix]=Buffer.concat(chunks).toString('utf8');
    await artifact.saveAs(info.outputPath(suffix));
  }
  const match=/Base64.strict_decode64\('([^']+)'\)/.exec(contents.customized_demo_firewall!);
  expect(match).not.toBeNull();
  const project=JSON.parse(Buffer.from(match![1]!,'base64').toString('utf8'));
  expect(project.extraction.format).toBe(format);
  await writeFile(info.outputPath('source-and-project.json'),JSON.stringify({raw,project},null,2));
  await page.screenshot({path:info.outputPath('downloaded-draft.png'),fullPage:true});
  await page.getByRole('navigation',{name:'Auto Parser steps'}).getByRole('button',{name:/Add Logs/}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(raw);
  return project;
}

test.beforeEach(async({page})=>{
  await page.goto('/');
});

test('strict RFC5424 structured data and free-form MSG reach actual parser downloads',async({page},info)=>{
  test.setTimeout(75000);
  await analyze(page,fixtures.rfc5424);
  const project=await downloadDraft(page,info,fixtures.rfc5424,'syslog_rfc5424');
  expect(project.extraction.syslogBodyFormat??'raw').toBe('raw');
  expect(Object.keys({...project.normalization.topFields,...project.normalization.nsFields,...project.normalization.vendorFields})).toEqual(expect.arrayContaining(['message','syslog_structured_data']));
});

test('generic Syslog description followed by strict key values reaches actual parser downloads',async({page},info)=>{
  test.setTimeout(75000);
  await analyze(page,fixtures.prefixedKv);
  const project=await downloadDraft(page,info,fixtures.prefixedKv,'generic_structural');
  expect(Object.keys({...project.normalization.topFields,...project.normalization.nsFields,...project.normalization.vendorFields})).toEqual(expect.arrayContaining(['generic.kv.signature','generic.kv.src','generic.kv.dst','generic.kv.action']));
});

test('original implicit TAB LEEF reaches parser downloads without changing source',async({page},info)=>{
  test.setTimeout(75000);
  await analyze(page,fixtures.implicitTabLeef);
  const project=await downloadDraft(page,info,fixtures.implicitTabLeef,'generic_structural');
  expect(project.extraction.genericStructuralProfile).toBe('leef2_implicit_tab');
  expect(Object.keys({...project.normalization.topFields,...project.normalization.nsFields,...project.normalization.vendorFields})).toEqual(expect.arrayContaining(['leef_header.vendor','leef_header.product','leef_extension.usrName','leef_extension.src','leef_extension.dst','leef_extension.url','leef_extension.action']));
});
