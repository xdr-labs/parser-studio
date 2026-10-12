import { expect, test } from '@playwright/test';

test('nondeveloper adds a safe constant enrichment and sees it in backend-only project metadata', async ({ page }) => {
  const cap = {
    contract:'host-customized-pair.v0.1', projectSchemaRevision:'0.1',
    authoring: { receiverProtocols:['udp','tcp'], extractionFormats:['json','kv','csv','cef','leef','syslog_rfc5424'],
      formatCoverage:'reviewed-bounded-subset', httpReceiver:false, multipleDistinctReceiverPorts:false,
      multiline:false, arbitraryRuby:false },
    import:{ exactInternalPairsEditable:true, unknownLegacyRubyEditable:false, structuralInspectionOnly:true },
    verification:{ engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false },
    limits:{ maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152 },
  };
  await page.route('**/api/v1/parser-pairs/capabilities', route => route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(cap),
  }));
  const posted: unknown[] = [];
  await page.route('**/api/v1/parser-pairs/validate', route => {
    posted.push(route.request().postDataJSON());
    return route.fulfill({ status:200,contentType:'application/json',body:JSON.stringify({ ok:true,issues:[] }) });
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill('{"action":"deny","src_ip":"198.51.100.13","dst_port":443}');
  await page.getByRole('button', { name: /2\. Extract Fields/ }).click();
  await page.getByRole('button', { name: 'JSON', exact:true }).click();
  await page.getByRole('button', { name: /3\. Map Fields/ }).click();
  await page.getByRole('button', { name: 'Add Enrichment Step' }).click();
  await page.getByLabel('Enrichment target 0').fill('custom.site');
  await page.getByLabel('Enrichment value 0').fill('seoul');
  await page.getByRole('button', { name: /5\. Test & Fix/ }).click();
  await page.getByRole('button', { name: 'Run Full Browser Test' }).click();
  await page.getByRole('button', { name: /6\. Generate Files/ }).click();
  await page.getByRole('button', { name: 'Validate Backend Input' }).click();
  await expect(page.getByText('Schema PASS · Engine Unverified')).toBeVisible();
  expect(posted).toHaveLength(1);
  expect((posted[0] as { enrichment: unknown[] }).enrichment).toEqual([
    {operator:'set_const',target:'custom.site',value:'seoul'},
  ]);
  expect(JSON.stringify(posted[0])).not.toContain('198.51.100.13');
});
