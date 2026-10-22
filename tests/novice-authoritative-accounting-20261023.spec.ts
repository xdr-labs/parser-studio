import {test,expect} from '@playwright/test';

test('initial scan never masquerades as final parser analysis',async({page})=>{
  await page.goto('/');
  const source=[
    '{"timestamp":"2026-10-23T08:00:01Z","src_ip":"192.0.2.1","action":"allow"}',
    '{"timestamp":"2026-10-23T08:00:02Z","src_ip":"192.0.2.2","action":"deny"}',
  ].join('\n');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  const ledger=page.getByLabel('Automatic event accounting');
  await expect(ledger).toContainText('events checked in the initial format scan');
  await expect(ledger).toContainText('Initial scan only');
  await expect(ledger.getByLabel('Full parser analysis accounting')).toHaveCount(0);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('2 of 2 log events parsed completely',{timeout:25000});
  const final=ledger.getByLabel('Full parser analysis accounting');
  await expect(final).toContainText(/Full parser analysis:\s*2\s*\/\s*2 logical events/);
  await expect(final).toContainText('0 need review');
});

test('CSV review cannot be contradicted by the preliminary format census',async({page})=>{
  await page.goto('/');
  const source=[
    '"2026-10-23T08:07:11Z","TRAFFIC","192.0.2.82","198.51.100.83","443","allow"',
    '"2026-10-23T08:07:12Z","THREAT","192.0.2.84","198.51.100.85","22","deny"',
  ].join('\n');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('0 of 2 log events parsed completely',{timeout:25000});
  const ledger=page.getByLabel('Automatic event accounting');
  await expect(ledger.getByLabel('Full parser analysis accounting')).toContainText(/2 need review/);
  await expect(ledger).toContainText('initial format scan');
  const csv=page.getByLabel('Review CSV column names');
  await expect(csv).toBeVisible();
  await csv.getByLabel('Reviewed CSV column names').fill('event_time,event_type,src_ip,dst_ip,dst_port,action');
  await csv.getByRole('button',{name:'I Confirm These CSV Column Names'}).click();
  await expect(csv).toContainText('Field names are ready');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});

test('W3C headers are distinguished from actual source events',async({page})=>{
  const source=[
    '#Version: 1.0',
    '#Date: 2026-10-23 08:00:00',
    '#Fields: date time c-ip cs-method cs-uri-stem sc-status',
    '2026-10-23 08:09:11 192.0.2.91 POST /login 403',
    '2026-10-23 08:09:12 192.0.2.92 GET /index.html 200',
  ].join('\n');
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(source);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('0 of 2 log events parsed completely',{timeout:25000});
  const ledger=page.getByLabel('Automatic event accounting');
  await expect(ledger).toContainText('initial format scan');
  await expect(ledger.getByLabel('Full parser analysis accounting')).toContainText(/2 need review/);
  await expect(ledger).toContainText('schema/header lines are source metadata, not log events');
  await expect(ledger).toContainText('initial format scan and full analysis count different units');
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
});
