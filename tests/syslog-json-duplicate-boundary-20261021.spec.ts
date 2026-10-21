import {test,expect} from '@playwright/test';

// Fully authored bounded source examples, not customer or manufacturer logs.
const rfc5424='<34>1 2026-10-21T00:00:00Z gw app 1 EV01 - ';
const rfc3164='<134>Jan 16 15:19:05 gw app: ';
const malformed=[
  '{"src_ip":"192.0.2.10","src_ip":"198.51.100.10"}',
  '{"outer":{"username":"first","username":"second"}}',
  '{"\\u0061":"one","a":"two"}',
  '{"items":[{"action":"allow","action":"deny"}]}',
];
const proper='{"left":{"username":"김민수"},"right":{"username":"山田"}}';

test('actual browser rejects duplicate JSON inside explicit RFC5424/3164 before normalizing',async({page})=>{
  const errors:string[]=[];
  const serverErrors:number[]=[];
  page.on('pageerror',err=>errors.push(err.message));
  page.on('response',response=>{
    if(response.url().includes('/api/')&&response.status()>=500)serverErrors.push(response.status());
  });
  await page.goto('/');
  const observations=await page.evaluate(async({malformed,rfc5424,rfc3164,proper})=>{
    const module=await import('/src/structuredFamilies.ts');
    return {
      rejected:[
        ...malformed.map(body=>module.extractStructuredFamily(rfc5424+body,'syslog_rfc5424','json')),
        ...malformed.map(body=>module.extractStructuredFamily(rfc3164+body,'syslog_rfc3164','json')),
      ],
      accepted:[
        module.extractStructuredFamily(rfc5424+proper,'syslog_rfc5424','json'),
        module.extractStructuredFamily(rfc3164+proper,'syslog_rfc3164','json'),
      ],
    };
  },{malformed,rfc5424,rfc3164,proper});
  expect(observations.rejected).toHaveLength(8);
  for(const result of observations.rejected){
    expect(result.fields).toEqual({});
    expect(result.errors).toContain('Duplicate JSON object key in reviewed Syslog body');
  }
  for(const result of observations.accepted){
    expect(result.errors).toEqual([]);
    expect(result.fields.body).toMatchObject({
      left:{username:'김민수'},right:{username:'山田'},
    });
  }
  // The novice must not be guided to generate a DRAFT for a lossy body.
  const raw=rfc5424+malformed[0]!;
  const source=page.getByLabel('Auto Parser raw logs');
  await source.fill(raw);
  await page.getByRole('button',{name:'Analyze Logs',exact:true}).click();
  await expect(source).toHaveValue(raw);
  await expect(page.getByRole('button',{name:'Review Fields',exact:true})).toBeDisabled();
  expect(errors).toEqual([]);
  expect(serverErrors).toEqual([]);
});

test('multiline browser grouping treats duplicate JSON names as ambiguous rather than parsed',async({page})=>{
  await page.goto('/');
  const results=await page.evaluate(async()=>{
    const {reviewLogicalBoundaries}=await import('/src/guided/logicalBoundaryReview.ts');
    return {
      repeated:reviewLogicalBoundaries('{\n "src_ip":"192.0.2.10",\n "src_ip":"198.51.100.10"\n}'),
      escaped:reviewLogicalBoundaries('{\n "\\u0061":"one",\n "a":"two"\n}'),
      valid:reviewLogicalBoundaries('{\n "left":{"username":"김민수"},\n "right":{"username":"山田"}\n}'),
    };
  });
  for(const result of [results.repeated,results.escaped]){
    expect(result).toMatchObject({
      status:'REVIEW_REQUIRED',ambiguousCount:1,multilineEventCount:0,sourceIncluded:false,
      nativeVerified:false,targetVerified:false,
    });
    expect(result.groups[0]).toMatchObject({kind:'JSON_OBJECT',status:'AMBIGUOUS'});
    expect(JSON.stringify(result)).not.toContain('192.0.2.10');
    expect(JSON.stringify(result)).not.toContain('username');
  }
  expect(results.valid).toMatchObject({
    status:'REVIEWABLE_MULTILINE',ambiguousCount:0,multilineEventCount:1,sourceIncluded:false,
  });
});
