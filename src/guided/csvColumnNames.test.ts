import {describe,expect,it} from 'vitest';
import {describeCsvColumnNameProblem} from './csvColumnNames';

describe('reviewed CSV column names explain why Confirm stays disabled',()=>{
  it('accepts unique identifier-like names',()=>{
    expect(describeCsvColumnNameProblem(['ts','gen','sid'])).toBeNull();
  });
  it('names the duplicated column',()=>{
    expect(describeCsvColumnNameProblem(['ts','ts','sid'])).toContain('"ts" is used more than once');
  });
  it('points at a name with a space or symbol',()=>{
    const message=describeCsvColumnNameProblem(['ts','bad name!','sid']);
    expect(message).toContain('"bad name!"');
    expect(message).toMatch(/start with a letter/i);
  });
  it('points at a name that starts with a digit',()=>{
    expect(describeCsvColumnNameProblem(['ts','1st','sid'])).toContain('"1st"');
  });
  it('explains an empty name caused by a stray comma',()=>{
    expect(describeCsvColumnNameProblem(['ts','','sid'])).toMatch(/empty name/i);
  });
  it('explains a name longer than 64 characters without echoing all of it',()=>{
    const message=describeCsvColumnNameProblem(['ts','a'.repeat(65)])!;
    expect(message).toMatch(/64 characters/);
    expect(message.length).toBeLessThan(220);
  });
  it('limits the number of names to 100',()=>{
    const names=Array.from({length:101},(_,i)=>'c'+i);
    expect(describeCsvColumnNameProblem(names)).toMatch(/at most 100/);
  });
  it('needs at least two names',()=>{
    expect(describeCsvColumnNameProblem(['only'])).toMatch(/at least 2/);
  });
});
