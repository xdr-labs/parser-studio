import {describe,expect,it} from 'vitest';
import type {MultiPassSourcePreview} from './multipassPreviewClient';
import {buildMultiPassSourceHighlights} from './multipassSourceHighlights';

function preview(overrides:Partial<MultiPassSourcePreview>={}):MultiPassSourcePreview{
 return {contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',syntax:'KV',
  sourceSha256:'0'.repeat(64),sourceBytes:0,fields:{},spans:[],residuals:[],issues:[],
  nativeVerified:false,targetVerified:false,...overrides};
}

describe('Multi-Pass exact source highlight map',()=>{
 it('reconstructs exact raw source and exposes parsed field plus residual selections',()=>{
  const raw='src=192.0.2.1 tail=?';
  const result=buildMultiPassSourceHighlights(raw,preview({
   spans:[{path:'src',startByte:4,endByte:13}],residuals:[{startByte:14,endByte:20}],
  }));
  expect(result.ok).toBe(true);
  if(!result.ok)return;
  expect(result.segments.map(item=>item.text).join('')).toBe(raw);
  expect(result.selectable).toEqual([
   {kind:'field',path:'src',startByte:4,endByte:13,text:'192.0.2.1'},
   {kind:'residual',startByte:14,endByte:20,text:'tail=?'},
  ]);
 });
 it('uses UTF-8 byte offsets without splitting multibyte source text',()=>{
  const raw='user=José action=allow';
  const bytes=new TextEncoder();
  const start=bytes.encode('user=').byteLength;
  const end=bytes.encode('user=José').byteLength;
  const result=buildMultiPassSourceHighlights(raw,preview({spans:[{path:'user',startByte:start,endByte:end}]}));
  expect(result.ok).toBe(true);
  if(!result.ok)return;
  expect(result.selectable[0]).toMatchObject({kind:'field',path:'user',text:'José',startByte:start,endByte:end});
  expect(result.segments.map(item=>item.text).join('')).toBe(raw);
 });
 it('handles real ASA-style residuals containing accepted fields without losing either selection',()=>{
  const raw='%ASA-4-106023: Deny udp src outside:192.0.2.1/53';
  const result=buildMultiPassSourceHighlights(raw,preview({
   spans:[
    {path:'asa.product',startByte:1,endByte:4},
    {path:'asa.severity',startByte:5,endByte:6},
    {path:'asa.message_id',startByte:7,endByte:13},
    {path:'asa.action',startByte:15,endByte:19},
    {path:'asa.protocol',startByte:20,endByte:23},
   ],residuals:[{startByte:15,endByte:new TextEncoder().encode(raw).byteLength}],
  }));
  expect(result.ok).toBe(true);
  if(!result.ok)return;
  expect(result.segments.map(item=>item.text).join('')).toBe(raw);
  expect(result.segments.filter(item=>item.kind==='field').map(item=>item.text)).toEqual(['ASA','4','106023','Deny','udp']);
  const residual=result.selectable.find(item=>item.kind==='residual');
  expect(residual?.text).toBe('Deny udp src outside:192.0.2.1/53');
  expect(result.segments.filter(item=>item.kind==='residual').map(item=>item.text).join('')).toBe('  src outside:192.0.2.1/53');
 });
 it('fails closed only when multiple extracted fields overlap ambiguously',()=>{
  const raw='abcdef';
  const result=buildMultiPassSourceHighlights(raw,preview({
   spans:[{path:'a',startByte:0,endByte:4},{path:'b',startByte:3,endByte:6}],
  }));
  expect(result).toEqual({ok:false,reason:'AMBIGUOUS_FIELD_OVERLAP'});
 });
});
