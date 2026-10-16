import {describe,expect,it} from 'vitest';
import {createDraft,type EventResult} from '../model';
import {buildParserExplain} from './parserExplain';

function event(fields:Record<string,unknown>):EventResult{
  return {
    id:'event-1',line:1,raw:'sample',
    detected:{format:'generic_structural',confidence:1,reason:'bounded structure'},
    effectiveFormat:'generic_structural',fields,normalized:{},unmapped:[],
    matched:true,extracted:true,normalizedOk:true,status:'pass',diagnostics:[],
    trace:[{stage:'Event boundary',detail:'Physical line 1',ok:true}],
  };
}

describe('parser explanation',()=>{
  it('explains Syslog plus PAN-OS and reports preserved schema drift',()=>{
    const draft=createDraft();
    draft.format='generic_structural';
    draft.mappings=[
      {id:'src',source:'generic.fields.src',target:'srcip',type:'ip'},
      {id:'dst',source:'generic.fields.dst',target:'dstip',type:'ip'},
    ];
    const report=buildParserExplain(event({
      syslog:{pri:'14',month:'Oct',day:'15',time:'00:03:21',hostname:'PA-FW01'},
      generic:{mode:'panos_traffic_csv',source_raw:'sample',fields:{
        src:'10.0.0.1',dst:'8.8.8.8',vendor_extra_001:'future',
      }},
    }),draft,'SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV');
    expect(report.steps).toEqual(expect.arrayContaining([
      expect.objectContaining({id:'envelope',
        summary:'Syslog envelope fields were separated before the message body.',
        details:expect.arrayContaining(['PRI: 14','Host: PA-FW01'])}),
      expect.objectContaining({id:'format',
        summary:expect.stringContaining('Palo Alto Networks PAN-OS TRAFFIC ordered CSV'),
        details:expect.arrayContaining([
          'Engine path: SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV',
          expect.stringContaining('preserved without shifting known columns'),
        ])}),
      expect.objectContaining({id:'mapping',status:'PASS',
        summary:expect.stringContaining('2 of 2')}),
    ]));
    expect(report.parsedLeafCount).toBeGreaterThan(2);
  });

  it('keeps native compatibility as a separate evidence gate',()=>{
    const report=buildParserExplain(event({json:{action:'allow'}}),createDraft());
    expect(report.steps.at(-1)).toMatchObject({
      id:'compatibility',status:'INFO',
      title:'Verification scope',
      summary:'Native Fluentd and Stellar target import verification remain separate evidence gates.',
    });
  });
});
