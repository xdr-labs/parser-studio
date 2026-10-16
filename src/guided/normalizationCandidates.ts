import type {MappingRule} from '../model';

export interface NormalizationCandidate {
 source:string;
 target:string;
 type:MappingRule['type'];
 confidence:'HIGH'|'REVIEW';
 explanation:string;
 catalogVerified:false;
}
// Browser-only alias hints. These are NOT an official Stellar Cyber field catalog.
const HINTS:Record<string,{target:string;type:MappingRule['type']}>= {
 src_ip:{target:'srcip',type:'ip'},source_ip:{target:'srcip',type:'ip'},
 dst_ip:{target:'dstip',type:'ip'},destination_ip:{target:'dstip',type:'ip'},
 src_port:{target:'srcport',type:'port'},source_port:{target:'srcport',type:'port'},
 dst_port:{target:'dstport',type:'port'},destination_port:{target:'dstport',type:'port'},
};
const SAFE=/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
export function suggestNormalizationCandidates(
 fields:Record<string,unknown>,existing:MappingRule[]):NormalizationCandidate[]{
 const taken=new Set(existing.map(rule=>rule.source));
 const outputs=new Set(existing.map(rule=>rule.target));
 const proposed:NormalizationCandidate[]=[];
 for(const [source,value] of Object.entries(fields).slice(0,100)){
   if(!SAFE.test(source)||source.split('.').some(x=>['__proto__','constructor','prototype'].includes(x))||taken.has(source))continue;
   const hint=HINTS[source.toLowerCase()];
   if(!hint||outputs.has(hint.target)||proposed.some(x=>x.target===hint.target))continue;
   const valid=hint.type==='ip'?typeof value==='string'&&/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)&&value.split('.').every(x=>Number(x)<=255):
     hint.type==='port'&&(typeof value==='number'||typeof value==='string')&&/^\d+$/.test(String(value))&&Number(value)>=0&&Number(value)<=65535;
   proposed.push({source,target:hint.target,type:hint.type,confidence:valid?'HIGH':'REVIEW',
     explanation:valid?'Field-name alias and sample value shape agree.':'Field-name alias only; value needs review.',catalogVerified:false});
   outputs.add(hint.target);
 }
 return proposed;
}
