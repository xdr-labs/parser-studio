import {test,expect} from './support/downloadSink';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

interface Golden {sourcePath:string;sourceValue:unknown}
interface VendorCase {id:string;sampleClass:string;rawSample:string;goldenSourceValues:Golden[]}
const corpus=JSON.parse(readFileSync(resolve('evals/chatgpt/security-cases.json'),'utf8')) as
  {cases:VendorCase[]};
const cap={
  contract:'host-customized-pair.v0.1',projectSchemaRevision:'0.1',
  authoring:{receiverProtocols:['udp','tcp'],
    extractionFormats:['json','kv','csv','syslog_rfc5424','cef','leef'],
    rfc5424BodyFormats:['raw','json','kv','cef','leef'],
    rfc5424AdjacentStructuredDataSubset:true,rfc5424StructuredDataMaxBytes:1024,
    leefHexSeparatorSubset:true,formatCoverage:'reviewed-bounded-subset',
    httpReceiver:false,multipleDistinctReceiverPorts:false,
    multiline:false,arbitraryRuby:false},
  import:{exactInternalPairsEditable:true,unknownLegacyRubyEditable:false,structuralInspectionOnly:true},
  verification:{engineVerified:false,targetImportVerified:false,liveListenerVerified:false,proprietaryLoaderVerified:false},
  downloads:{individualGeneratedFiles:true,zipWithManifest:true,requiresDpConnection:false,
    requiresApiKey:false,autoDeploys:false,exactArtifactRevision:true},
  limits:{maxProjectBodyBytes:262144,maxInspectBodyBytes:2097152},
};

const vendorCases=corpus.cases.filter(item=>item.sampleClass.startsWith('VENDOR_DOCUMENTED'));

// These are publisher-documented examples bundled with their source references.
// Two JSON records were compacted in the original evaluation corpus; they are
// not presented here as byte-identical excerpts from the vendor documentation.
for(const vendorCase of vendorCases){
  test('documented security-log source and mapping review · '+vendorCase.id,async({page})=>{
    await page.route('**/api/v1/parser-pairs/capabilities',route=>
      route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(cap)}));
    await page.goto('/');
    await page.getByLabel('Auto Parser raw logs').fill(vendorCase.rawSample);
    await expect(page.getByLabel('Automatic event accounting')).toContainText('1/1 events analyzed locally');
    await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
    await expect(page.getByLabel('Beginner analysis summary'))
      .toContainText('1 of 1 log event structurally parsed',{timeout:20_000});
    const review=page.getByRole('button',{name:'Review Fields',exact:true});
    await expect(review).toBeEnabled();
    await review.click();
    await page.getByLabel('Review Fields stage').getByRole('button',{name:'Map Fields'}).click();
    const map=page.getByLabel('Map Fields stage');
    await expect(map).toBeVisible();
    const sourcePre=map.locator('.normalization-full-preview > div:nth-child(2) pre');
    const parsed=JSON.parse((await sourcePre.textContent())??'{}') as unknown;
    const leaves:unknown[]=[];
    const visit=(node:unknown):void=>{
      if(node!==null&&typeof node==='object'){
        if(Array.isArray(node))node.forEach(visit);
        else Object.values(node).forEach(visit);
      }else leaves.push(node);
    };
    visit(parsed);
    for(const golden of vendorCase.goldenSourceValues){
      expect(leaves.some(value=>String(value)===String(golden.sourceValue)),
        vendorCase.id+': source value not extracted: '+golden.sourcePath).toBe(true);
    }
    const destinations=await map.locator('.normalization-diff-list > div > strong:nth-of-type(2)')
      .allTextContents();
    expect(destinations.length).toBeGreaterThan(0);
    expect(destinations.every(item=>!item.startsWith('Demo Local Draft.'))).toBe(true);
    const fields=await map.locator('.normalization-map-row input[aria-label^="Stellar field "]')
      .evaluateAll(nodes=>nodes.map(node=>(node as HTMLInputElement).value));
    // The editor groups official rows first and collapses long vendor lists;
    // the comparison contains all mappings in draft order.
    expect(destinations.length).toBeGreaterThanOrEqual(fields.length);
    for(const field of fields)expect(destinations).toContain(field);
    await expect(map.getByText('Nothing is sent to a Stellar Cyber system from this screen.'))
      .toBeVisible();
  });
}
