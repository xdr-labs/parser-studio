import {describe,expect,it} from 'vitest';
import {existsSync,readdirSync,readFileSync,statSync} from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

/**
 * English applies to authored product chrome, explanations and comments, NOT
 * to the bytes or language of security logs. Raw log examples and test
 * fixtures are data and must never be translated or rejected for Unicode.
 */
const NON_ENGLISH_SCRIPT=/[\uAC00-\uD7A3\u3040-\u30FF\u3400-\u9FFF]/u;
const CODE_EXTENSIONS=new Set(['.ts','.tsx','.js','.jsx','.mjs']);
const DOCUMENT_EXTENSIONS=new Set(['.md','.mdx','.css','.html','.yaml','.yml']);
const OMIT=new Set(['node_modules','dist','.git','test-results','playwright-report','coverage']);
const LOG_FENCE=/^\s*\x60{3,}(?:log|raw|syslog|cef|leef|json|csv|kv|text|plaintext|xml)\b/i;

function collect(root:string,extensions:Set<string>):string[]{
  if(!existsSync(root))return [];
  const output:string[]=[];
  for(const entry of readdirSync(root,{withFileTypes:true})){
    if(OMIT.has(entry.name))continue;
    const filename=path.join(root,entry.name);
    if(entry.isDirectory())output.push(...collect(filename,extensions));
    else if(entry.isFile()&&extensions.has(path.extname(filename)))
      output.push(filename);
  }
  return output;
}

/** Fenced source-log examples are data, not authored explanatory paragraphs. */
function authoredDocumentViolations(content:string):number[]{
  let fence=false,logFence=false;
  const bad:number[]=[];
  content.split('\n').forEach((line,index)=>{
    if(/^\s*\x60{3,}/.test(line)){
      if(!fence){fence=true;logFence=LOG_FENCE.test(line);}
      else{fence=false;logFence=false;}
      return;
    }
    if((!fence||!logFence)&&NON_ENGLISH_SCRIPT.test(line))bad.push(index+1);
  });
  return bad;
}

/**
 * TypeScript syntax-aware check. Comments, visible JSX copy, accessibility
 * attributes and test titles are authored prose. Other strings may be raw
 * logs, field values or fixtures and are not language-restricted.
 */
function authoredCodeViolations(filename:string,content:string):number[]{
  const src=ts.createSourceFile(filename,content,ts.ScriptTarget.Latest,true,
    filename.endsWith('.tsx')?ts.ScriptKind.TSX:ts.ScriptKind.TS);
  const positions:number[]=[];
  const check=(value:string,position:number)=>{
    if(NON_ENGLISH_SCRIPT.test(value))
      positions.push(src.getLineAndCharacterOfPosition(position).line+1);
  };
  const scanner=ts.createScanner(ts.ScriptTarget.Latest,false,ts.LanguageVariant.Standard,content);
  let kind=scanner.scan();
  while(kind!==ts.SyntaxKind.EndOfFileToken){
    if(kind===ts.SyntaxKind.SingleLineCommentTrivia||
       kind===ts.SyntaxKind.MultiLineCommentTrivia)
      check(scanner.getTokenText(),scanner.getTokenPos());
    kind=scanner.scan();
  }
  const walk=(node:ts.Node)=>{
    if(ts.isJsxText(node))check(node.getText(src),node.getStart(src));
    if(ts.isJsxAttribute(node)&&node.initializer&&ts.isStringLiteral(node.initializer))
      check(node.initializer.text,node.initializer.getStart(src));
    if(ts.isJsxExpression(node)&&node.expression&&ts.isStringLiteralLike(node.expression))
      check(node.expression.text,node.expression.getStart(src));
    if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)&&
       ['it','test','describe'].includes(node.expression.text)){
      const label=node.arguments[0];
      if(label&&ts.isStringLiteralLike(label))check(label.text,label.getStart(src));
    }
    ts.forEachChild(node,walk);
  };
  walk(src);
  return [...new Set(positions)].sort((a,b)=>a-b);
}

describe('English authored presentation and multilingual security log data',()=>{
  it('keeps authored prose, visible UI labels, comments and test names in English',()=>{
    const root=process.cwd();
    const sources=['src','tests','e2e'].flatMap(dir=>
      collect(path.join(root,dir),CODE_EXTENSIONS));
    const documents=['docs','.engineering','.github'].flatMap(dir=>
      collect(path.join(root,dir),DOCUMENT_EXTENSIONS));
    documents.push(...['README.md','AGENTS.md','index.html']
      .map(filename=>path.join(root,filename)));
    const violations:string[]=[];
    for(const filename of sources){
      const content=readFileSync(filename,'utf8');
      for(const line of authoredCodeViolations(filename,content))
        violations.push(path.relative(root,filename)+':'+line);
    }
    for(const filename of documents){
      if(!existsSync(filename)||!statSync(filename).isFile())continue;
      const content=readFileSync(filename,'utf8');
      for(const line of authoredDocumentViolations(content))
        violations.push(path.relative(root,filename)+':'+line);
    }
    expect(violations,'Non-English authored UI/prose (not log fixture data)').toEqual([]);
  },20_000);

  it('allows multilingual logs but catches non-English UI copy',()=>{
    const log='{"message":"로그인 실패","user":"山田","location":"北京"}';
    const fixtureCode='const rawLog='+JSON.stringify(log)+';';
    expect(authoredCodeViolations('example.test.ts',fixtureCode)).toEqual([]);
    expect(authoredCodeViolations('sample.tsx',
      '<button aria-label="설정">確認</button>')).toEqual([1]);
    const fence=String.fromCharCode(96).repeat(3);
    expect(authoredDocumentViolations('Usage instructions in English.\n'+
      fence+'log\n'+log+'\n'+fence+'\n'+
      'Review the original values.')).toEqual([]);
    expect(authoredDocumentViolations('User instructions in English.\n설정 방법')).toEqual([2]);
  });

  it('uses an English UI locale and does not restrict customer log language',()=>{
    const root=process.cwd();
    const app=readFileSync(path.join(root,'src/App.tsx'),'utf8');
    const auto=readFileSync(path.join(root,'src/guided/AutoParser.tsx'),'utf8');
    const assisted=readFileSync(path.join(root,'src/guided/ChatGPTAssist.tsx'),'utf8');
    expect(app).not.toContain("'ko-KR'");
    expect(auto).not.toContain('Ask ChatGPT about an unfamiliar log');
    expect(app).toContain('ChatGPT Assisted Parser');
    expect(assisted).toContain('ChatGPT Assisted Parser');
    expect(app).toContain('Auto Parser');
    expect(app).not.toContain("workspace==='guided'");
    expect(app).not.toContain("workspace==='expert'");
    const readme=readFileSync(path.join(root,'README.md'),'utf8');
    expect(readme).toMatch(/<strong>English<\/strong>/);
    expect(readme).not.toContain('Korean-first');
    const html=readFileSync(path.join(root,'index.html'),'utf8');
    expect(html).toContain('lang="en"');
  });
});
