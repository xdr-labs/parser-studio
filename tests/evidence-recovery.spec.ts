import {test,expect} from '@playwright/test';

/**
 * Owner scope 2026-10-18: the two-path product no longer offers Test Lab
 * recovery/evidence, sensor sending, or Interflow lookups. Preserve the
 * negative trust-boundary contract against the real SHA-pinned localhost
 * backend instead of testing removed user-facing controls.
 */
test.describe('removed sensor/evidence UI and default-deny backend boundary',()=>{
  test.skip(process.env.PARSER_STUDIO_LIVE_BACKEND!=='1',
    'Requires exact pinned localhost compiler/backend acceptance, never a sensor.');

  const runId='test_run_'+'a'.repeat(32);

  test('ordinary Auto Parser review never exposes Test Lab, Interflow or sensor commands',async({page})=>{
    const forbiddenRequests:string[]=[];
    page.on('request',request=>{
      const path=new URL(request.url()).pathname;
      if(path.startsWith('/api/v1/test-lab/')||
         path.startsWith('/api/v1/parser-pairs/target/apply')||
         path.includes('/interflow/'))forbiddenRequests.push(path);
    });
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs')
      .fill('{"src_ip":"192.0.2.10","action":"deny","dst_port":443}');
    await page.getByRole('button',{name:'Analyze Logs'}).click();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toContainText('structurally parsed');
    await expect(page.getByRole('button',{name:'Advanced Tools & Diagnostics'})).toHaveCount(0);
    for(const removed of [
      'Authorized Test Lab session recovery',
      'Authorized Test Lab offline evidence',
      'Approved synthetic Sensor Replay',
      'Interflow field comparison after approved replay',
      'Active Test Lab session indicator',
      'Authorized test and Interflow verification',
    ])await expect(page.getByLabel(removed,{exact:true})).toHaveCount(0);
    for(const button of [
      'Look Up My Authorized Run',
      'Start Approved Synthetic Session',
      'Read Authorized Interflow Comparison',
      'Download Verified Redacted Evidence JSON',
    ])await expect(page.getByRole('button',{name:button,exact:true})).toHaveCount(0);
    await page.getByRole('button',{name:'Review Fields',exact:true}).click();
    await expect(page.getByLabel('Review Fields stage')).toBeVisible();
    await page.getByRole('button',{name:'Map Fields',exact:true}).click();
    await expect(page.getByLabel('Map Fields stage')).toBeVisible();
    await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
    await expect(page.getByLabel('Create Parser stage')).toBeVisible();
    expect(forbiddenRequests).toEqual([]);
  });

  test('removed owner evidence endpoints fail closed with no injected authorization',async({request})=>{
    const paths=[
      '/api/v1/test-lab/sessions/status?runId='+runId,
      '/api/v1/test-lab/sessions/evidence-summary?runId='+runId,
      '/api/v1/test-lab/sessions/evidence-export?runId='+runId,
    ];
    for(const path of paths){
      const response=await request.get(path);
      // Disabled endpoints may explicitly deny (403) or be absent (404).
      // Both must remain non-successful and must never return owner evidence.
      expect([403,404],path).toContain(response.status());
      const body=await response.json();
      expect(body).toHaveProperty('error');
      expect(['TESTLAB_SENDER_DISABLED','NOT_FOUND','AUTHORING_ONLY_ROUTE_NOT_AVAILABLE'],path)
        .toContain(body.error);
      const text=JSON.stringify(body);
      expect(text).not.toContain('PRIVATE_CUSTOMER_VALUE');
      expect(text).not.toContain('apiKey');
    }
  });
});
