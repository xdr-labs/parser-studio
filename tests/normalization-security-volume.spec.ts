import {test,expect,type Page} from '@playwright/test';
import {verifyOfficialMappings} from './normalizationAcceptance';

const cap={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],rfc5424AdjacentStructuredDataSubset:true,
    rfc5424StructuredDataMaxBytes:1024,leefHexSeparatorSubset:true,
    formatCoverage:'reviewed-bounded-subset',httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

function ip(prefix:number,i:number){return '192.0.'+prefix+'.'+(i%250+1);}
function dst(prefix:number,i:number){return '198.51.'+prefix+'.'+(i%250+1);}

const batches=[
  {
    name:'100 flat JSON firewall events',
    targets:['srcip','dstip','srcport','dstport','action','hostname'],
    rows:Array.from({length:100},(_,i)=>JSON.stringify({
      src_ip:ip(10,i),dst_ip:dst(10,i),src_port:40000+i,dst_port:i%2?443:80,
      action:i%3?'allow':'deny',hostname:'json-fw-'+String(i+1).padStart(3,'0'),
    })),
  },
  {
    name:'100 nested ECS/XDR events',
    targets:['srcip','dstip','srcport','dstport','action','hostname','timestamp'],
    rows:Array.from({length:100},(_,i)=>JSON.stringify({
      source:{address:ip(20,i),port:41000+i},
      destination:{address:dst(20,i),port:i%2?443:53},
      event:{action:i%4?'allow':'deny',timestamp:new Date(Date.UTC(2026,9,16,3,0,i)).toISOString()},
      host:{name:'nested-'+String(i+1).padStart(3,'0')},
    })),
  },
  {
    name:'100 CEF security events',
    targets:['srcip','dstip','srcport','dstport','action'],
    rows:Array.from({length:100},(_,i)=>
      'CEF:0|Vendor|NGFW|1|'+(1000+i)+'|Session|5|src='+ip(30,i)+' dst='+dst(30,i)+
      ' spt='+(42000+i)+' dpt='+(i%2?443:80)+' act='+(i%5?'allow':'deny')+' cs1=rule-'+i),
  },
  {
    name:'100 LEEF security events',
    targets:['srcip','dstip','srcport','dstport','action'],
    rows:Array.from({length:100},(_,i)=>
      'LEEF:1.0|Vendor|Firewall|1|'+(2000+i)+'|src='+ip(40,i)+'\tdst='+dst(40,i)+
      '\tsrcPort='+(43000+i)+'\tdstPort='+(i%2?443:53)+'\taction='+(i%5?'allow':'deny')),
  },
  {
    name:'100 KV firewall events',
    targets:['srcip','dstip','srcport','dstport','action','hostname'],
    rows:Array.from({length:100},(_,i)=>
      'srcip='+ip(50,i)+' dstip='+dst(50,i)+' srcport='+(44000+i)+' dstport='+
      (i%2?443:22)+' action='+(i%4?'accept':'deny')+' hostname=kv-fw-'+(i+1)),
  },
  {
    name:'100 Windows Event JSON records',
    targets:['hostname','source_name','record_number','task','opcode','keywords','log_name','username','severity'],
    rows:Array.from({length:100},(_,i)=>JSON.stringify({
      hostname:'win-'+String(i+1).padStart(3,'0'),
      source_name:i%2?'Microsoft-Windows-Security-Auditing':'Microsoft-Windows-PowerShell',
      record_number:String(50000+i),task:i%2?'Logon':'Execute',opcode:'Info',
      keywords:i%3?'Audit Success':'Audit Failure',
      log_name:i%2?'Security':'Microsoft-Windows-PowerShell/Operational',
      username:'user'+(i+1),severity:i%5===0?60:10,
    })),
  },
] as const;

async function mapBatch(page:Page,rows:readonly string[]){
  await page.route('**/api/v1/parser-pairs/capabilities',route=>
    route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
  await page.goto('/');
  await page.getByRole('button',{name:'Advanced'}).click();
  await page.getByLabel('Auto Parser raw logs').fill(rows.join('\n'));
  await expect(page.getByLabel('Automatic event accounting'))
    .toContainText(rows.length+'/'+rows.length+' events analyzed locally',{timeout:15000});
  const review=page.getByRole('button',{name:'Review Detected Results'});
  await expect(review).toBeEnabled({timeout:15000});
  await review.click();
  await expect(page.getByLabel('Review Fields stage')).toBeVisible({timeout:15000});
  await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
  const map=page.getByLabel('Map Fields stage');
  await expect(map).toBeVisible();
  return map;
}

for(const batch of batches){
  test('normalization volume E2E · '+batch.name,async({page})=>{
    const map=await mapBatch(page,batch.rows);
    await verifyOfficialMappings(map,batch.targets,batch.name);
  });
}
