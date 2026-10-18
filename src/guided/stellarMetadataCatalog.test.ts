import {describe,it,expect} from 'vitest';
import {
  findStellarMetadataField,searchStellarMetadataCatalog,STELLAR_METADATA_CATALOG,
  STELLAR_METADATA_CATALOG_PROVENANCE,
} from './stellarMetadataCatalog';

describe('revision-pinned Stellar public metadata catalog',()=>{
  it('records authoritative public-document provenance without claiming target runtime evidence',()=>{
    expect(STELLAR_METADATA_CATALOG_PROVENANCE).toMatchObject({
      release:'7.0.xs',evidence:'PUBLIC_VENDOR_DOCUMENTATION',
      sourceSha256:'6577a72da962561ad9c0cfb726e1dc0bdf1a95e17df3ebfe63a0156e3c408053',
    });
    expect(STELLAR_METADATA_CATALOG.length).toBeGreaterThan(250);
  });
  it('maps documented scalar field types into the supported authoring contract',()=>{
    expect(findStellarMetadataField('srcip')).toMatchObject({documentedTypes:['ip'],mappingType:'ip',mappable:true,group:'top_fields'});
    expect(findStellarMetadataField('dstport')).toMatchObject({documentedTypes:['integer'],mappingType:'integer',mappable:true});
    expect(findStellarMetadataField('timestamp')).toMatchObject({documentedTypes:['date'],mappingType:'timestamp',mappable:true});
  });
  it('fails closed for ambiguous, object, unsupported and runtime-reserved fields',()=>{
    expect(findStellarMetadataField('host')).toMatchObject({documentedTypes:['object','string'],mappable:false,reason:'AMBIGUOUS_TYPE'});
    expect(findStellarMetadataField('msg_origin')).toMatchObject({mappable:false,reason:'RESERVED_RUNTIME_FIELD'});
    expect(findStellarMetadataField('parser_err_msg')).toMatchObject({mappable:false,reason:'RESERVED_RUNTIME_FIELD'});
  });
  it('provides bounded case-insensitive catalog search',()=>{
    expect(searchStellarMetadataCatalog('src',5).length).toBeLessThanOrEqual(5);
    expect(searchStellarMetadataCatalog('SRCIP',10).some(entry=>entry.name==='srcip')).toBe(true);
    expect(searchStellarMetadataCatalog('Source IP address',10).some(entry=>entry.name==='srcip')).toBe(true);
    expect(findStellarMetadataField('srcip')?.descriptions[0]).toContain('Source IP address');
  });
});
