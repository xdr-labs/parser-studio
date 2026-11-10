import {test,expect} from './support/downloadSink';
import {readFile} from 'node:fs/promises';

test('a first-time desktop user saves logs, generates actual files, and restores the source',async({page},info)=>{
  // The historical independent compatibility backend intentionally lacks the
  // newest inverted Syslog fallback. Keep an exact-source browser CI gate.
  test.skip(process.env.PARSER_STUDIO_BACKEND_HEAD==='03624952a8c097e5423df32b40ec64137f029f49',
    'Current source compiler acceptance runs in the exact-head web-quality gate.');
  const source=[
    '{"timestamp":"2026-10-23T08:11:22Z","event_type":"alert","src_ip":"192.0.2.10","dst_port":443,"action":"deny"}',
    '{"timestamp":"2026-10-23T08:11:23Z","event_type":"alert","src_ip":"192.0.2.11","dst_port":22,"action":"allow"}',
  ].join('\n');
  const browserErrors:string[]=[];
  page.on('pageerror',error=>browserErrors.push(error.message));
  await page.setViewportSize({width:1280,height:800});
  await page.goto('/');
  await expect(page.getByRole('main',{name:'Auto Parser v2'})).toBeVisible();
  const raw=page.getByLabel('Auto Parser raw logs');
  const bounds=await raw.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.y).toBeLessThan(710);
  await raw.fill(source);
  await page.getByLabel('Parser manufacturer').fill('Example Network Vendor');
  await page.getByLabel('Parser product',{exact:true}).fill('Example Firewall');
  await page.getByLabel('Parser product version').fill('9.4');
  await page.getByLabel('Parser listener port').fill('6819');
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const history=page.getByLabel('Local Versions workspace');
  await expect(history).toBeVisible();
  await history.getByLabel('Local version name').fill('First real browser sample');
  await history.getByRole('button',{name:'Save Version'}).click();
  await expect(history).toContainText('Saved in this browser only');
  await history.getByRole('button',{name:'Close Versions'}).click();

  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Beginner analysis summary'))
    .toContainText('2 of 2 log events structurally parsed',{timeout:20000});
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled();
  await review.click();
  await expect(page.getByLabel('Browser-only event inspector')).toContainText('192.0.2.10');
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  await expect(page.getByLabel('Map Fields stage')).toBeVisible();
  await page.getByLabel('Map Fields stage').getByRole('button',{name:'Create Parser'}).click();
  await expect(page.getByLabel('Create Parser stage')).toBeVisible();
  await page.getByRole('button',{name:'Create Parser Files'}).click();
  const files=page.getByLabel('Generated parser files');
  await expect(files).toContainText('Parser files created successfully',{timeout:20000});
  await expect(files).toContainText('Native runtime and Stellar target verification are separate; nothing was deployed.');
  const confPromise=page.waitForEvent('download');
  await files.getByRole('button',{name:/customized_example_network_vendor_example_firewall\.conf/}).click();
  const conf=await confPromise;
  const confText=await readFile(await conf.path(),'utf8');
  expect(confText).toMatch(/^\s+port 6819$/m);
  expect(confText).toMatch(/invert true/);
  const logicPromise=page.waitForEvent('download');
  await files.getByRole('button',{name:/customized_example_network_vendor_example_firewall$/,exact:true}).click();
  const ruby=await logicPromise;
  const logic=await readFile(await ruby.path(),'utf8');
  expect(logic).toContain('Base64.strict_decode64');
  const zipPromise=page.waitForEvent('download');
  await files.getByRole('button',{name:'Download Parser Package'}).click();
  const zip=await zipPromise;
  const zipped=await readFile(await zip.path());
  expect(zipped.subarray(0,2).toString('ascii')).toBe('PK');

  page.once('dialog',dialog=>dialog.accept());
  await page.getByRole('button',{name:'New Parser',exact:true}).click();
  await expect(raw).toBeEmpty();
  await page.getByRole('button',{name:'Local Versions',exact:true}).click();
  const restored=page.getByLabel('Local Versions workspace');
  await expect(restored.getByLabel('Saved local versions').getByText('First real browser sample')).toBeVisible();
  page.once('dialog',dialog=>dialog.accept());
  await restored.getByRole('button',{name:'Restore'}).click();
  await expect(page.getByLabel('Auto Parser raw logs')).toHaveValue(source);
  await expect(page.getByLabel('Parser manufacturer')).toHaveValue('Example Network Vendor');
  await expect(page.getByLabel('Parser product',{exact:true})).toHaveValue('Example Firewall');
  await expect(page.getByLabel('Parser listener port')).toHaveValue('6819');
  expect(browserErrors).toEqual([]);
});
