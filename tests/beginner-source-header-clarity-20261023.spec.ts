import {test,expect} from '@playwright/test';

const sources=[
  {
    label:'W3C',
    metadata:2,
    raw:[
      '#Version: 1.0',
      '#Fields: date time c-ip cs-method cs-uri-stem sc-status',
      '2026-10-23 08:11:22 192.0.2.12 GET /admin 403',
      '2026-10-23 08:11:23 192.0.2.13 POST /login 200',
    ].join('\n'),
  },
  {
    label:'Zeek',
    metadata:7,
    raw:[
      '#separator \\x09',
      '#set_separator\t,',
      '#empty_field\t(empty)',
      '#unset_field\t-',
      '#path\tconn',
      '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto',
      '#types\ttime\tstring\taddr\tport\taddr\tport\tenum',
      '1792743082.000000\tC1\t192.0.2.10\t55000\t198.51.100.5\t443\ttcp',
      '1792743083.000000\tC2\t192.0.2.11\t55001\t198.51.100.6\t22\ttcp',
    ].join('\n'),
  },
] as const;

for(const item of sources){
  test(item.label+' header metadata and data events are explained separately without claiming native parser readiness',async({page})=>{
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(item.raw);
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(page.getByLabel('Beginner analysis summary')).toBeVisible({timeout:20000});
    const explanation=page.getByLabel('Source header versus data event explanation');
    await expect(explanation).toBeVisible({timeout:20000});
    await expect(explanation).toContainText('2 data events');
    await expect(explanation).toContainText(item.metadata+' schema/header lines');
    await expect(explanation).toContainText('not additional data events');
    const accounting=page.getByLabel('Header and data event accounting');
    await expect(accounting).toContainText('2 data events');
    await expect(accounting).toContainText(item.metadata+' original schema/header lines kept separately');
    await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toContainText('downloadable parser compiler');
  });
}

test('positional CSV summary updates from needing review to reviewed and ready',async({page})=>{
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill([
    '\"2026-10-23T08:11:22Z\",\"192.0.2.10\",\"198.51.100.5\",\"deny\"',
    '\"2026-10-23T08:11:23Z\",\"192.0.2.11\",\"198.51.100.6\",\"allow\"',
  ].join('\n'));
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('0 of 2 log events parsed completely',{timeout:20000});
  await page.getByLabel('Reviewed CSV column names').fill('timestamp,src_ip,dst_ip,action');
  await page.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('2 of 2 log events parsed completely',{timeout:20000});
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
});
