import {test,expect,type Page} from '@playwright/test';

// A Syslog-wrapped PAN-OS record as a Syslog server stores it: the PRI is gone. The first scan reads the line as
// positional CSV without column names; the bounded compiler reads the record. The same record with a PRI was
// already adopted automatically (tests/common-security-logs.spec.ts).
const PAN_WITHOUT_PRI="Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy";
// Plain positional rows that no bounded grammar names: the CSV column review must stay.
const PLAIN_CSV='alpha,10.0.0.1,443,allow\nbravo,10.0.0.2,80,deny';
// RFC 5424 gives an SD-ELEMENT no maximum length; a Junos session-close element is longer than 1 KiB.
const head='<14>1 2026-11-21T09:15:22.123Z srx01 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.129 ';
const flow=(source:string,padding:number)=>head+'reason="TCP FIN" source-address="'+source+
  '" source-port="47776" destination-address="198.51.100.15" destination-port="80" protocol-id="6"'+
  Array.from({length:padding},(_,index)=>' application-field-'+String(index).padStart(3,'0')+'="value-'+'x'.repeat(24)+'"').join('')+']';

async function analyze(page:Page,raw:string){
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
}
async function openMappings(page:Page){
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled({timeout:10_000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  const map=page.getByRole('button',{name:'Map Fields',exact:true});
  await expect(map).toBeEnabled({timeout:10_000});
  await map.click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  const editor=page.getByLabel('Field mapping editor');
  return async(source:string,target:string)=>{
    const row=editor.locator('article.normalization-map-row[data-source-path="'+source+'"]');
    await expect(row,'one mapping row for source '+source).toHaveCount(1);
    await expect(row.locator('input[aria-label^="Stellar field "]')).toHaveValue(target);
  };
}

test('PAN-OS traffic Syslog without a PRI is adopted like the same record with a PRI',async({page})=>{
  await analyze(page,PAN_WITHOUT_PRI);
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('1 of 1 log event structurally parsed',{timeout:15_000});
  await expect(page.getByText('I Confirm These CSV Column Names')).toHaveCount(0);
  const expectMapping=await openMappings(page);
  await expectMapping('generic.fields.src','srcip');
  await expectMapping('generic.fields.dst','dstip');
  await expectMapping('generic.fields.sport','srcport');
  await expectMapping('generic.fields.dport','dstport');
  await expectMapping('generic.fields.protocol','proto_name');
  await expectMapping('generic.fields.action','action');
});

test('plain positional CSV rows keep the column review',async({page})=>{
  await analyze(page,PLAIN_CSV);
  await expect(page.getByText('consistent columns detected')).toBeVisible({timeout:15_000});
  await expect(page.getByText('I Confirm These CSV Column Names')).toBeVisible();
});

test('Junos RT_FLOW records with a structured-data element above 1 KiB are parsed and mapped',async({page})=>{
  const long=flow('10.3.255.203',40),short=flow('10.3.255.204',0);
  expect(new TextEncoder().encode(long).byteLength).toBeGreaterThan(1024+head.length);
  await analyze(page,short+'\n'+long);
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('2 of 2 log events structurally parsed',{timeout:15_000});
  const expectMapping=await openMappings(page);
  await expectMapping('junos_sd.source_address','srcip');
  await expectMapping('junos_sd.destination_address','dstip');
  await expectMapping('junos_sd.source_port','srcport');
  await expectMapping('junos_sd.destination_port','dstport');
  await expectMapping('junos_sd.protocol_id','proto');
});
