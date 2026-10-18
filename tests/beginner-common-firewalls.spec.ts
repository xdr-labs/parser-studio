import {test,expect} from '@playwright/test';
import {createHash} from 'node:crypto';

const cap={
  contract:'host-customized-pair.v0.1',
  projectSchemaRevision:'0.1',
  authoring:{
    receiverProtocols:['udp','tcp'],
    extractionFormats:['generic_structural'],
    genericStructuralGrammar:'GENERIC_STRUCTURAL_ULTRA_COMPILER_V15',
    formatCoverage:'reviewed-bounded-subset',
    httpReceiver:false,multipleDistinctReceiverPorts:false,multiline:false,arbitraryRuby:false,
  },
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const multipass=(raw:string,syntax:string,fields:Record<string,unknown>)=>({
  contract:'parser-studio.multipass-source-preview.v0.1',
  status:'SOURCE_PARSED',syntax,sourceSha256:sha(raw),sourceBytes:Buffer.byteLength(raw),
  fields,spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
});
async function routeLocalAnalysis(page:any,raw:string,syntax:string,fields:Record<string,unknown>){
  await page.route('**/api/v1/multipass/preview',route=>{
    expect(route.request().postDataJSON()).toEqual({raw});
    return route.fulfill({status:200,contentType:'application/json',
      body:JSON.stringify(multipass(raw,syntax,fields))});
  });
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
}

test('common PAN-OS Traffic syslog is auto-adopted and mapped without a repair click',async({page})=>{
  const raw='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy';
  await routeLocalAnalysis(page,raw,'SECURITY_SYSLOG_ENVELOPE+GENERIC_POSITIONAL_CSV',{
    syslog:{pri:'14',month:'Oct',day:'15',time:'00:03:21',hostname:'PA-FW01'},
    body:{column_3:'TRAFFIC'},
  });
  await page.goto('/');
  await expect(page.getByRole('complementary',{name:'Parser Studio navigation'}).locator('button.rail-link')).toHaveCount(2);
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('parsed completely',{timeout:10000});
  await expect(page.getByRole('button',{name:'Use extracted fields'})).toHaveCount(0);
  const review=page.getByRole('button',{name:'Review Fields',exact:true});
  await expect(review).toBeEnabled();
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible();
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map.getByLabel(/Source field/).filter({hasText:''}).first()).toBeVisible();
  await expect(map).toContainText('parserstudio_source.generic.fields.src');
  await expect(map).toContainText('srcip');
  await expect(map).toContainText('parserstudio_source.generic.fields.dst');
  await expect(map).toContainText('dstip');
  await expect(map).toContainText('parserstudio_source.generic.fields.protocol');
  await expect(map).toContainText('proto_name');
  await expect(map).toContainText('parserstudio_source.generic.fields.action');
});

test('common year-bearing ASA 302013 wrapper is auto-adopted as a complete event',async({page})=>{
  const raw='<166>Oct 15 2026 00:05:03 ASA-EDGE01 : %ASA-6-302013: Built outbound TCP connection 18745213 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)';
  await routeLocalAnalysis(page,raw,'CISCO_ASA_FTD_MESSAGE_ID_FULL',{
    syslog:{pri:'166',month:'Oct',day:'15',year:'2026',time:'00:05:03',hostname:'ASA-EDGE01'},
    asa:{action:'Built',protocol:'TCP',src_ip:'203.0.113.50',dst_ip:'10.1.15.27'},
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('parsed completely',{timeout:10000});
  await expect(page.getByRole('button',{name:'Use extracted fields'})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeEnabled();
});

test('BIG-IP ASM comma KV is auto-adopted and nested leaf names drive Stellar suggestions',async({page})=>{
  const raw='Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname="bigip-waf01",management_ip_address="10.1.1.10",request_status="blocked",ip_client="203.0.113.210",route_domain="0",method="POST",protocol="HTTPS",date_time="2026-10-15T00:14:27+09:00",dest_port="443",dest_ip="10.20.1.25",uri="/api/login"';
  await routeLocalAnalysis(page,raw,'GENERIC_BSD_ENVELOPE+DELIMITED_KV',{
    syslog:{month:'Oct',day:'15',time:'00:14:27',host:'bigip-waf01',tag:'ASM'},
    generic:{mode:'delimited_kv'},
  });
  await page.goto('/');
  await page.getByLabel('Auto Parser raw logs').fill(raw);
  await page.getByRole('button',{name:'Analyze Logs'}).click();
  await expect(page.getByLabel('Beginner analysis summary')).toContainText('parsed completely',{timeout:10000});
  await expect(page.getByRole('button',{name:'Use extracted fields'})).toHaveCount(0);
  await page.getByRole('button',{name:'Review Fields',exact:true}).click();
  await page.getByRole('button',{name:'Map Fields',exact:true}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toContainText('parserstudio_source.generic.fields.ip_client');
  await expect(map).toContainText('srcip');
  await expect(map).toContainText('parserstudio_source.generic.fields.dest_ip');
  await expect(map).toContainText('dstip');
  await expect(map).toContainText('parserstudio_source.generic.fields.protocol');
  await expect(map).toContainText('proto_name');
});
