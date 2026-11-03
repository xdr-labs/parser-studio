import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {sampleProject} from './fixture.js';
import {validateProject} from '../src/validate.js';
import {compilePair} from '../src/compiler.js';

const columns=['src_ip','detail','dst_port'];
const cases=[
  {delimiter:',',raw:'192.0.2.10,,443',values:['192.0.2.10',null,'443']},
  {delimiter:',',raw:'192.0.2.10,"",443',values:['192.0.2.10','','443']},
  {delimiter:',',raw:'192.0.2.10,  ,443',values:['192.0.2.10',null,'443']},
  {delimiter:',',raw:',deny,443',values:[null,'deny','443']},
  {delimiter:',',raw:'192.0.2.10,deny,',values:['192.0.2.10','deny',null]},
  {delimiter:',',raw:'192.0.2.10,"  ",443',values:['192.0.2.10','  ','443']},
  {delimiter:';',raw:'192.0.2.10;;443',values:['192.0.2.10',null,'443']},
  {delimiter:';',raw:'192.0.2.10;"";443',values:['192.0.2.10','','443']},
  {delimiter:';',raw:'192.0.2.10;  ;443',values:['192.0.2.10',null,'443']},
  {delimiter:'\t',raw:'192.0.2.10\t\t443',values:['192.0.2.10',null,'443']},
  {delimiter:'\t',raw:'192.0.2.10\t""\t443',values:['192.0.2.10','','443']},
  {delimiter:'\t',raw:'192.0.2.10\t  \t443',values:['192.0.2.10','  ','443']},
  {delimiter:'\t',raw:' 192.0.2.10 \tdeny\t 443 ',values:[' 192.0.2.10 ','deny',' 443 ']},
  {delimiter:'\t',raw:'192.0.2.10\t"  "\t443',values:['192.0.2.10','  ','443']},
] as const;

test('strict generated Ruby parser preserves exact reviewed CSV null, empty and TAB whitespace cells',()=>{
  const runner=[
    "require 'csv'",
    "require 'json'",
    'input=JSON.parse(STDIN.read)',
    'klass=Class.new',
    "klass.class_eval(input.fetch('source'),'generated_csv_parity',1)",
    'parser=klass.new',
    "settings={'csvColumns'=>input.fetch('columns'),'csvDelimiter'=>input.fetch('delimiter')}",
    'rows=input.fetch("samples").map do |sample|',
    '  begin',
    '    parser.parserstudio_csv(sample,settings)',
    '  rescue => error',
    "    {'error'=>error.class.name}",
    '  end',
    'end',
    'record=nil',
    "parser.parse(input.fetch('smoke')){|_time,event|record=event}",
    'STDOUT.write(JSON.generate({rows:rows,record:record}))',
  ].join('\n');
  for(const delimiter of [',',';','\t'] as const){
    const project=sampleProject();
    project.projectId='synthetic-csv-null-native-parity';
    project.slug='csv_null_native_parity';
    project.extraction={format:'csv',csvColumns:columns,csvDelimiter:delimiter};
    project.normalization.topFields={
      src_ip:{normalized_name:'srcip',data_type:'ip'},
      dst_port:{normalized_name:'dstport',data_type:'port'},
    };
    project.normalization.nsFields={};
    project.normalization.vendorFields={
      detail:{normalized_name:'detail',data_type:'string'},
    };
    project.classification.rules=[];
    const validation=validateProject(project);
    assert.equal(validation.ok,true,JSON.stringify(validation.issues));
    const pair=compilePair(project);
    assert.equal(pair.manifest.engineVerified,false);
    assert.equal(pair.manifest.targetImportVerified,false);
    const ruby=pair.files.find(file=>file.name==='customized_csv_null_native_parity');
    assert.ok(ruby);
    const samples=cases.filter(item=>item.delimiter===delimiter);
    const smoke=['192.0.2.10','','443'].join(delimiter);
    const child=spawnSync(process.env.PARSER_RUBY_BIN||'ruby',['-e',runner],{
      input:JSON.stringify({source:ruby.content,columns,delimiter,
        samples:samples.map(item=>item.raw),smoke}),
      encoding:'utf8',timeout:15000,maxBuffer:1024*1024,
    });
    assert.equal(child.status,0,String(child.stderr));
    const native=JSON.parse(child.stdout) as {
      rows:Array<Record<string,string|null>>;
      record:Record<string,unknown>;
    };
    assert.deepEqual(native.rows,samples.map(item=>({
      src_ip:item.values[0],detail:item.values[1],dst_port:item.values[2]
    })));
    assert.equal(native.record.parser_err_msg,undefined);
    assert.equal(native.record.srcip,'192.0.2.10');
    assert.equal(native.record.dstport,443);
  }
});
