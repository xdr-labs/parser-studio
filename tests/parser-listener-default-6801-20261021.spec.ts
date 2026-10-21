import {expect,test} from '@playwright/test';

const samples='"allow","198.51.100.10"\n"deny","203.0.113.4"\n"allow","192.0.2.8"';

for(const [scenario,listenerPort] of [
  ['new parser default',6801],
  ['explicit log source override',6905],
] as const){
  test(`${scenario} appears at first log source entry and reaches downloaded CONF`,async({page})=>{
    test.skip(process.env.PARSER_STUDIO_SCOPED_AUTHORING_E2E!=='1',
      'Requires exact-HEAD offline authoring backend and genuine Python Multi-Pass.');
    test.setTimeout(90_000);
    const errors:string[]=[];
    page.on('pageerror',error=>errors.push(error.message));
    page.on('response',response=>{
      if(response.url().includes('/api/')&&response.status()>=500)
        errors.push(`HTTP ${response.status()}: ${response.url()}`);
    });
    await page.goto('/');
    const port=page.getByLabel('Parser listener port');
    await expect(port).toBeVisible();
    await expect(port).toHaveValue('6801');
    if(listenerPort!==6801)await port.fill(String(listenerPort));
    await expect(page.getByLabel('Parser product identity')).toContainText(`CONF listener port: ${listenerPort}`);
    await page.getByRole('button',{name:'Go to log input'}).click();
    await expect(page.getByLabel('Auto Parser raw logs')).toBeFocused();
    await page.getByLabel('Auto Parser raw logs').fill(samples);
    await expect(page.getByLabel('Automatic event accounting')).toContainText('3/3 events checked');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    const csv=page.getByLabel('Review CSV column names');
    await expect(csv).toContainText('2 consistent columns detected');
    await csv.getByLabel('Reviewed CSV column names').fill('action,src_ip');
    await csv.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
    await page.getByRole('button',{name:'Review Fields',exact:true}).click();
    await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields',exact:true}).click();
    await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser',exact:true}).click();
    await page.getByLabel('Create Parser Files').click();
    const result=page.getByLabel('Generated parser files');
    await expect(result).toContainText('Parser files created successfully',{timeout:30_000});
    const downloadPromise=page.waitForEvent('download');
    await result.getByRole('button',{name:/customized_demo_firewall\.conf$/}).click();
    const download=await downloadPromise;
    const reader=await download.createReadStream();
    const buffers:Buffer[]=[];
    for await(const chunk of reader)buffers.push(Buffer.from(chunk));
    const conf=Buffer.concat(buffers).toString('utf8');
    const configPorts=[...conf.matchAll(/^\s+port (\d+)\s*$/gm)].map(match=>Number(match[1]));
    expect(configPorts.length).toBeGreaterThan(0);
    expect([...new Set(configPorts)]).toEqual([listenerPort]);
    await page.getByRole('navigation',{name:'Auto Parser steps'})
      .getByRole('button',{name:/Add Logs/}).click();
    await expect(page.getByLabel('Parser listener port')).toHaveValue(String(listenerPort));
    await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(samples);
    expect(errors).toEqual([]);
  });
}
