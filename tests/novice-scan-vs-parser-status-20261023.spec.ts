import {test,expect} from '@playwright/test';

const cases=[
  {
    name:'positional CSV',
    raw:'"2026-10-23T08:07:11Z","TRAFFIC","192.0.2.82","198.51.100.83","443","allow"\n"2026-10-23T08:07:12Z","THREAT","192.0.2.84","198.51.100.85","22","deny"',
    eventCount:2,
  },
  {
    name:'W3C schema-header stream',
    raw:'#Version: 1.0\n#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-23 08:09:11 192.0.2.91 POST /login 403\n2026-10-23 08:09:12 192.0.2.92 GET /index.html 200',
    eventCount:2,
  },
] as const;

for(const item of cases){
  test(item.name+' distinguishes the early format census from final review requirements',async({page})=>{
    const errors:string[]=[];
    page.on('pageerror',e=>errors.push(e.message));
    await page.goto('/');
    const input=page.getByLabel('Auto Parser raw logs');
    await input.fill(item.raw);
    const ledger=page.getByLabel('Automatic event accounting');
    await expect(ledger).toContainText('initial format scan');
    await expect(ledger).toContainText('not a parser completeness result');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const final=page.getByLabel('Beginner analysis summary');
    await expect(final).toContainText('0 of '+item.eventCount+' log events structurally parsed',{timeout:25000});
    await expect(final).toContainText(item.eventCount+' events need attention');
    await expect(ledger).toContainText('initial format scan');
    await expect(ledger.getByLabel('Full parser analysis accounting'))
      .toContainText('Use the full parser analysis summary');
    await expect(ledger).not.toContainText('0 events need attention');
    await expect(input).toHaveValue(item.raw);
    expect(errors).toEqual([]);
  });
}
