import {expect,test,type Page} from '@playwright/test';

const cap={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    httpReceiver:false,multipleDistinctReceiverPorts:false,formatCoverage:'reviewed-bounded-subset',
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],
    rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:1024,
    leefHexSeparatorSubset:true,multiline:false,arbitraryRuby:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,
    proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const envelope=(page:Page)=>page.getByLabel('Auto Parser envelope and body review');
const source3164='<34>Oct 12 13:14:15 fw01 sec: action="allow" src_ip=198.51.100.10 user=PRIVATE_USER';
const source5424='<34>1 2026-10-12T12:00:00Z fw app - - - {"action":"allow","user":{"name":"PRIVATE_USER"}}';
test('novice reviews RFC3164 wrapped KV as unsupported without sending sample bytes or selecting parser',async({page})=>{
  let gets=0,posts=0;
  await page.route('**/api/v1/parser-pairs/capabilities',route=>{
    gets++;
    expect(route.request().method()).toBe('GET');
    expect(route.request().postData()).toBe(null);
    return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)});
  });
  page.on('request',request=>{if(request.method()==='POST'&&request.url().includes('/api/v1/'))posts++;});
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(source3164);
  const block=envelope(page);
  expect(gets).toBe(0);
  await block.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const result=page.getByLabel('Auto Parser source ledger');
  await expect(result).toContainText('1/1 logical events accounted for');
  await expect(result).toContainText('COMPILER_UNSUPPORTED');
  await expect(result.getByLabel('Envelope body family totals')).toContainText('RFC3164 Syslog / Key / Value: 1');
  await expect(result).toContainText('Year/timezone ambiguous');
  for(const privateValue of ['PRIVATE_USER','198.51.100.10','fw01']){
    expect(await result.innerText()).not.toContain(privateValue);
  }
  await expect(block.getByRole('button',{name:'Apply analyzed draft candidate'})).toHaveCount(0);
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(source3164);
  expect(gets).toBe(1);expect(posts).toBe(0);
});
test('RFC5424 JSON recognized and explicitly selected as a draft candidate, without native/target PASS',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(source5424);
  const block=envelope(page);
  await block.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const result=page.getByLabel('Auto Parser source ledger');
  await expect(result).toContainText('DRAFT_COMPILABLE');
  await expect(result.getByLabel('Envelope body family totals')).toContainText('RFC5424 Syslog / JSON: 1');
  expect(await result.innerText()).not.toContain('PRIVATE_USER');
  await expect(result).toContainText('Native parser unverified');
  const apply=block.getByRole('button',{name:'Apply analyzed draft candidate'});
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect(apply).toBeDisabled();
  await page.getByRole('button',{name:/2\. Extract Fields/}).click();
  await expect(page.getByRole('button',{name:'RFC5424',exact:true})).toHaveAttribute('aria-pressed','true');
  await expect(page.getByLabel('RFC5424 message body format')).toHaveValue('json');
  await page.getByRole('button',{name:/1\. Import Logs/}).click();
  await expect(page.getByLabel('Guided raw sample logs')).toHaveValue(source5424);
});
test('mixed/unknown and multiline events are counted without a false single-format compiler green',async({page})=>{
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  const input=page.getByLabel('Guided raw sample logs');
  const block=envelope(page);
  await input.fill(source5424+'\n'+source3164+'\nUNRECOGNIZED_PRIVATE_RECORD');
  await block.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  const result=page.getByLabel('Auto Parser source ledger');
  await expect(result).toContainText('3/3 logical events accounted for');
  await expect(result).toContainText('1 need review');
  await expect(result).toContainText('MIXED_OR_UNKNOWN');
  expect(await result.innerText()).not.toContain('UNRECOGNIZED_PRIVATE_RECORD');
  await expect(block.getByRole('button',{name:'Apply analyzed draft candidate'})).toHaveCount(0);
  await input.fill('{\n  "action":"allow"\n}\n\n'+source3164);
  await page.getByRole('button',{name:/Separate events using blank lines/}).click();
  await block.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Auto Parser source ledger')).toContainText('BOUNDARY_REVIEW');
  await expect(page.getByLabel('Auto Parser source ledger')).toContainText('2/2 logical events');
});
test('server 403 and forged backend verification keep compilation unverified and source private',async({page})=>{
  let mode:'denied'|'forged'='denied';
  await page.route('**/api/v1/parser-pairs/capabilities',route=>{
    if(mode==='denied')return route.fulfill({status:403,contentType:'application/json',
      body:JSON.stringify({error:'CAPABILITY_DENIED',customer:'PRIVATE_USER'})});
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify({...cap,verification:{...cap.verification,targetImportVerified:true}})});
  });
  await page.goto('/');
  await page.getByLabel('Guided raw sample logs').fill(source5424);
  const block=envelope(page);
  await block.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Auto Parser source ledger')).toContainText('BACKEND_UNAVAILABLE');
  await expect(block.getByRole('button',{name:'Apply analyzed draft candidate'})).toHaveCount(0);
  mode='forged';
  await block.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(page.getByLabel('Auto Parser source ledger')).toContainText('BACKEND_UNAVAILABLE');
  expect(await block.innerText()).not.toContain('PRIVATE_USER');
});
