import {fireEvent,render,screen} from '@testing-library/react';
import {expect,it} from 'vitest';
import {HelpTip} from './BeginnerHelp';

it('closes contextual help on second click, outside click, and Escape',()=>{
  render(<div><HelpTip label="Source fields" text="Help details"/>
    <button type="button">Outside</button></div>);
  const button=screen.getByRole('button',{name:'Help: Source fields'});
  expect(button).toHaveAttribute('aria-expanded','false');
  fireEvent.click(button);
  expect(button).toHaveAttribute('aria-expanded','true');
  fireEvent.click(button);
  expect(button).toHaveAttribute('aria-expanded','false');
  fireEvent.click(button);
  fireEvent.pointerDown(screen.getByRole('button',{name:'Outside'}));
  expect(button).toHaveAttribute('aria-expanded','false');
  fireEvent.click(button);
  fireEvent.keyDown(button,{key:'Escape'});
  expect(button).toHaveAttribute('aria-expanded','false');
});
