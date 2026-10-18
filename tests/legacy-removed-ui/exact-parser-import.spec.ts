import { expect,test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { createDraft } from '../src/model';
import { toBackendProject } from '../src/guided/backendAdapter';

const conf='<source>\n  @type udp\n  port 7501\n  tag customized_demo_firewall\n</source>\n';
const fragment='# Synthetic, unexecuted test fixture.\n';
const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
const reviewed=createDraft();
reviewed.name='Imported Synthetic Firewall';
reviewed.vendor='Public Synthetic Vendor';
reviewed.format='json';
const initial=toBackendProject(reviewed);
if(!initial.ok)throw Error('Reviewed UI project did not validate');
const portableProject=initial.project;
const base={
  format:'host-customized-pair',name:'customized_demo_firewall',
  originalHashes:{conf:hash(conf),fragment:hash(fragment)},
  receiver:{protocols:['udp'],ports:[7501],sourceCount:1},
  fragment:{markersComplete:true,hasParseEntry:true,opaqueRuby:false},
  importStatus:'EDITABLE_EXACT',roundTripVerified:true,
  portableProject,diagnostics:[],warnings:[],
};
const capabilities={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv'],
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,
    multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,
    liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
async function selectExactPair(page:import('@playwright/test').Page){
  await page.goto('/?workspace=guided');
  await page.getByLabel('Guided raw sample logs').fill('PRIVATE_CUSTOMER_LOG_DO_NOT_STORE');
  await page.getByRole('button',{name:/6\. Generate Files/}).click();
  await page.locator('.guided-pair-inspect summary').click();
  await page.getByLabel('Inspect pair CONF').setInputFiles({
    name:'customized_demo_firewall.conf',mimeType:'text/plain',buffer:Buffer.from(conf),
  });
  await page.getByLabel('Inspect pair Ruby fragment').setInputFiles({
    name:'customized_demo_firewall',mimeType:'text/plain',buffer:Buffer.from(fragment),
  });
  await page.getByRole('button',{name:'Inspect Selected Pair (Read-only)'}).click();
  await expect(page.getByLabel('Parser pair inspection results')).toBeVisible();
}
test('only explicitly confirmed exact, verified project can replace the unsaved draft without saving logs',async({page})=>{
  let inspections=0,forbidden=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities),
  }));
  await page.route('**/api/v1/parser-pairs/inspect',route=>{
    inspections++;
    expect(route.request().postDataJSON()).toMatchObject({
      name:'customized_demo_firewall',confContent:conf,fragmentContent:fragment,
    });
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify(base),
    });
  });
  page.on('request',req=>{
    if(req.method()==='POST' && !req.url().includes('/parser-pairs/inspect'))forbidden++;
  });
  await selectExactPair(page);
  const review=page.getByLabel('Parser import compatibility review');
  await expect(review).toContainText('Exact Backend Pair');
  await expect(review).toContainText('Manual lossless Guided draft reconstruction available');
  const controls=page.getByLabel('Exact parser pair import controls');
  await expect(controls).toContainText('Optional Guided Draft Restore');
  const restore=controls.getByRole('button',{name:'Restore Exact Pair as Unsaved Draft'});
  await expect(restore).toBeDisabled();
  await controls.getByLabel('Confirm replace current parser draft').check();
  await expect(restore).toBeEnabled();
  await restore.click();
  await expect(page.locator('.guided-content-head h2')).toContainText('normalized');
  await expect(page.getByLabel('Mapping for src_ip')).toBeVisible();
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided parser name')).toHaveValue('Imported Synthetic Firewall');
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue('');
  const storage=await page.evaluate(()=>JSON.stringify(localStorage));
  expect(storage).not.toContain('PRIVATE_CUSTOMER_LOG_DO_NOT_STORE');
  expect(inspections).toBe(1);
  expect(forbidden).toBe(0);
});

test('a purported exact pair with non-roundtrippable extra metadata stays read-only',async({page})=>{
  let calls=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>route.fulfill({
    status:200,contentType:'application/json',body:JSON.stringify(capabilities),
  }));
  await page.route('**/api/v1/parser-pairs/inspect',route=>{
    calls++;
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify({
        ...base,portableProject:{...portableProject,projectId:'unreviewed-project-id'},
      }),
    });
  });
  await selectExactPair(page);
  const review=page.getByLabel('Parser import compatibility review');
  await expect(review).toContainText('Guided draft import unavailable');
  await expect(review).toContainText('cannot be');
  await expect(page.getByLabel('Exact parser pair import controls')).toHaveCount(0);
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue('PRIVATE_CUSTOMER_LOG_DO_NOT_STORE');
  expect(calls).toBe(1);
});
