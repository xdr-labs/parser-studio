import {describe,it,expect} from 'vitest';
import {tokenizeCSV,extractFields} from './parser';
import {createDraft} from './model';

describe('strict browser/native CSV empty-cell source parity',()=>{
  it.each([
    ['unquoted middle','192.0.2.10,,443',',',['192.0.2.10',null,'443']],
    ['quoted middle','192.0.2.10,"",443',',',['192.0.2.10','','443']],
    ['spaces-only middle','192.0.2.10,  ,443',',',['192.0.2.10',null,'443']],
    ['unquoted leading',',deny,443',',',[null,'deny','443']],
    ['unquoted trailing','192.0.2.10,deny,',',',['192.0.2.10','deny',null]],
    ['two empty fields',',,',',',[null,null,null]],
    ['quoted empty first','"",deny,443',',',['','deny','443']],
    ['semicolon middle','192.0.2.10;;443',';',['192.0.2.10',null,'443']],
    ['semicolon quoted','192.0.2.10;"";443',';',['192.0.2.10','','443']],
    ['TAB middle','192.0.2.10\t\t443','\t',['192.0.2.10',null,'443']],
    ['TAB quoted','192.0.2.10\t""\t443','\t',['192.0.2.10','','443']],
    ['TAB spaces-only is present','192.0.2.10\t  \t443','\t',['192.0.2.10','  ','443']],
    ['TAB padded unquoted value',' 192.0.2.10 \tdeny\t 443 ','\t',[' 192.0.2.10 ','deny',' 443 ']],
    ['TAB quoted whitespace','192.0.2.10\t" "\t443','\t',['192.0.2.10',' ','443']],
    ['quoted whitespace','" ",deny,443',',',[' ','deny','443']],
  ] as const)('%s retains quoted versus unquoted empties',(_name,raw,delimiter,expected)=>{
    expect(tokenizeCSV(raw,delimiter)).toEqual([...expected]);
    const draft=createDraft();
    draft.format='csv';draft.csvColumns='source,action,port';draft.csvDelimiter=delimiter;
    expect(extractFields(raw,'csv',draft)).toEqual({
      fields:{source:expected[0],action:expected[1],port:expected[2]},
      errors:[]
    });
  });

  it.each([
    ['TAB unquoted prefix before quote','a\t "x"\tb','\t'],
    ['TAB unquoted suffix after quote','a\t"x" \tb','\t'],
    ['comma malformed quote','a,"bad"suffix,b',','],
    ['semicolon malformed quote','a;"bad"suffix;b',';'],
  ] as const)('rejects malformed %s rather than fabricating a field',(_name,source,delimiter)=>{
    expect(tokenizeCSV(source,delimiter)).toBeNull();
  });
});


describe('TAB delimiter follows strict Ruby CSV strip:false whitespace rules',()=>{
  it.each([
    ['plain fields preserve their edge spaces',' a \t b \t c ',[' a ',' b ',' c ']],
    ['spaces-only unquoted field remains text','a\t  \tc',['a','  ','c']],
    ['explicit quoted empty still differs from missing','a\t""\tc',['a','','c']],
    ['whitespace inside quotes remains text','a\t"  "\tc',['a','  ','c']],
  ])('%s',(_name,raw,expected)=>{
    expect(tokenizeCSV(raw,'\t')).toEqual(expected);
    const draft=createDraft();
    draft.format='csv';draft.csvColumns='source,detail,port';draft.csvDelimiter='\t';
    expect(extractFields(raw,'csv',draft)).toEqual({
      fields:{source:expected[0],detail:expected[1],port:expected[2]},errors:[]
    });
  });

  it.each([
    ['space preceding quote','a\t ""\tc'],
    ['space following closed quote','a\t"ok" \tc'],
    ['quote inside unquoted field','a\tb"c\tdef'],
  ])('rejects %s',(_name,raw)=>{
    expect(tokenizeCSV(raw,'\t')).toBeNull();
  });
});
