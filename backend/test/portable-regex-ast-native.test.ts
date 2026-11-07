import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {
  PORTABLE_REGEX_AST_CONTRACT,parsePortableRegexAst,portableRegexIssue,
} from '../src/portable-regex.js';
import {validateBoundedRegexPattern} from '../src/validate.js';

type Match={input:string;expected:Record<string,string>|null};
type Corpus={pattern:string;names:string[];cases:Match[]};
const goldens:Corpus[]=[
  {
    pattern:String.raw`^action=(?<action>allow|deny)$`,
    names:['action'],
    cases:[
      {input:'action=allow',expected:{action:'allow'}},
      {input:'action=deny',expected:{action:'deny'}},
      {input:'action=ALLOW',expected:null},
    ],
  },
  {
    pattern:String.raw`^(?<month>\d{2})/(?<proto>TCP|UDP)$`,
    names:['month','proto'],
    cases:[
      {input:'07/TCP',expected:{month:'07',proto:'TCP'}},
      {input:'11/UDP',expected:{month:'11',proto:'UDP'}},
      {input:'7/TCP',expected:null},
    ],
  },
  {
    pattern:String.raw`^src=(?<ip>[\d.]+)\s+msg=(?<message>[^,]+)$`,
    names:['ip','message'],
    cases:[
      {input:'src=192.0.2.4 msg=허용됨',expected:{ip:'192.0.2.4',message:'허용됨'}},
      {input:'src=198.51.100.8 msg=blocked',expected:{ip:'198.51.100.8',message:'blocked'}},
      {input:'src=bad msg=blocked',expected:null},
    ],
  },
];
const rejected=[
  String.raw`(?=allow)(?<action>allow)`,
  String.raw`(?!deny)(?<action>allow)`,
  String.raw`(?i:(?<action>allow))`,
  String.raw`(?<action>\p{Letter}+)`,
  String.raw`(?<action>a{3,129})`,
];

test('H1 independent portable AST positive and negative corpus matches browser regex semantics',()=>{
  assert.equal(PORTABLE_REGEX_AST_CONTRACT,'parser-studio.portable-regex-ast.v1');
  for(const {pattern,names,cases} of goldens){
    const ast=parsePortableRegexAst(pattern);
    assert.equal(ast.ok,true,pattern);
    if(!ast.ok)continue;
    assert.deepEqual(ast.captureNames,names);
    assert.equal(portableRegexIssue(pattern),null,pattern);
    assert.equal(validateBoundedRegexPattern(pattern),null,pattern);
    for(const {input,expected} of cases){
      const actual=new RegExp(pattern).exec(input)?.groups??null;
      assert.deepEqual(actual?Object.fromEntries(Object.entries(actual)):null,expected,
        'independent JS truth '+pattern+' '+input);
    }
  }
  for(const pattern of rejected){
    assert.notEqual(portableRegexIssue(pattern),null,pattern);
    assert.notEqual(validateBoundedRegexPattern(pattern),null,pattern);
  }
});

const ruby=spawnSync('ruby',['-v'],{encoding:'utf8'});
const required=process.env.PARSER_STUDIO_NATIVE_CONFORMANCE_REQUIRED==='1';
test('H1 strict Native CI refuses missing executable',()=>{
  if(required)assert.equal(ruby.status,0,'Mandatory Ruby executable absent');
});
test('H1 Ruby regex engine matches independent UTF-8 named capture golden results',
  {skip:ruby.status!==0},()=>{
    const runner=[
      "require 'json'",
      "sets=JSON.parse(STDIN.read)",
      "rows=sets.map do |entry|",
      "  regex=Regexp.new(entry.fetch('pattern'))",
      "  entry.fetch('cases').map do |value|",
      "    match=regex.match(value)",
      "    match ? match.named_captures : nil",
      "  end",
      "end",
      "STDOUT.write(JSON.generate(rows))",
    ].join('\n');
    const input=goldens.map(({pattern,cases})=>({pattern,cases:cases.map(c=>c.input)}));
    const result=spawnSync('ruby',['-e',runner],{
      input:JSON.stringify(input),encoding:'utf8',timeout:15000,maxBuffer:512*1024,
    });
    assert.equal(result.status,0,result.stderr||String(result.error));
    assert.deepEqual(JSON.parse(result.stdout),goldens.map(g=>g.cases.map(c=>c.expected)));
  });
