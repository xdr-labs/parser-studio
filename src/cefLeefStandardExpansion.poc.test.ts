import {describe,expect,it} from 'vitest';
import {extractStructuredFamily} from './structuredFamilies';
import {extractGenericStructural} from './genericStructural';

describe('CEF and LEEF standard-compatibility PoC',()=>{
  it('accepts reviewed CEF versions 0 and 1 standalone and under Syslog',()=>{
    for(const version of ['0','1']){
      const raw=`CEF:${version}|Acme\\|Security|Endpoint\\\\Guard|1.0|100|Threat \\| detected|8|src=192.0.2.10 msg=Line1\\nLine2 cs1=a\\=b path=C:\\\\Temp\\\\file`;
      const parsed=extractStructuredFamily(raw,'cef');
      expect(parsed.errors,version).toEqual([]);
      expect(parsed.fields).toMatchObject({
        cef_version:version,
        cef_device_vendor:'Acme|Security',
        cef_device_product:'Endpoint\\Guard',
        cef_name:'Threat | detected',
        src:'192.0.2.10',
        msg:'Line1\nLine2',
        cs1:'a=b',
        path:'C:\\Temp\\file',
      });
      const wrapped=extractGenericStructural('<134>2026-10-16T15:44:21Z EDR01 agent: '+raw);
      expect(wrapped.errors,version).toEqual([]);
      expect((wrapped.fields.body as Record<string,unknown>).cef_version).toBe(version);
    }
  });

  it('rejects unsupported CEF versions and unsafe/malformed extension structures',()=>{
    const invalid=[
      'CEF:2|Vendor|Product|1|100|Name|5|src=192.0.2.1',
      'CEF:9|Vendor|Product|1|100|Name|5|src=192.0.2.1',
      'CEF:1|Vendor|Product|1|100|Name|5|src=192.0.2.1 src=198.51.100.1',
      'CEF:1|Vendor|Product|1|100|Name|5|constructor=bad',
      'CEF:1|Vendor|Product|1|100|Name|5|cef_version=9',
      'CEF:1|Vendor|Product|1|100|Name|5|msg=trailing\\',
      'CEF:1|Vendor|Product|1|100|Name|5|broken extension',
      'CEF:1|Vendor|Product|1|100|Name|5',
    ];
    const accepted=invalid.filter(raw=>extractStructuredFamily(raw,'cef').errors.length===0);
    console.log('CEF_STANDARD_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });

  it('accepts LEEF 2.0 x/0x hex delimiter forms including pipe and multibyte delimiters',()=>{
    const cases=[
      ['x5E','^','src=192.0.2.1^dst=198.51.100.1^act=deny'],
      ['0x005E','^','src=192.0.2.1^dst=198.51.100.1^act=deny'],
      ['x7C','|','src=192.0.2.1|dst=198.51.100.1|act=deny'],
      ['x00A6','¦','src=192.0.2.1¦dst=198.51.100.1¦act=deny'],
      ['x09','\t','src=192.0.2.1\tdst=198.51.100.1\tact=deny'],
    ] as const;
    for(const [token,,attributes] of cases){
      const raw='LEEF:2.0|Acme|NDR|1.0|evt|'+token+'|'+attributes;
      const parsed=extractStructuredFamily(raw,'leef');
      expect(parsed.errors,token).toEqual([]);
      expect(parsed.fields).toMatchObject({src:'192.0.2.1',dst:'198.51.100.1',act:'deny'});
    }
  });

  it('rejects unsafe LEEF delimiters, duplicate keys, and malformed tokens',()=>{
    const base='LEEF:2.0|Acme|NDR|1.0|evt|TOKEN|src=192.0.2.1DELIMdst=198.51.100.1DELIMact=deny';
    const invalid=[
      base.replace('TOKEN','x0000').replaceAll('DELIM','\0'),
      base.replace('TOKEN','x000A').replaceAll('DELIM','\n'),
      base.replace('TOKEN','x000D').replaceAll('DELIM','\r'),
      base.replace('TOKEN','x003D').replaceAll('DELIM','='),
      base.replace('TOKEN','x005C').replaceAll('DELIM','\\'),
      base.replace('TOKEN','xD800').replaceAll('DELIM','^'),
      base.replace('TOKEN','x12345').replaceAll('DELIM','^'),
      base.replace('TOKEN','xGG').replaceAll('DELIM','^'),
      'LEEF:2.0|Acme|NDR|1.0|evt|^|src=192.0.2.1^src=198.51.100.1^act=deny',
      'LEEF:2.0|Acme|NDR|1.0|evt|^|constructor=bad^dst=198.51.100.1^act=deny',
    ];
    const accepted=invalid.filter(raw=>extractStructuredFamily(raw,'leef').errors.length===0);
    console.log('LEEF_STANDARD_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
