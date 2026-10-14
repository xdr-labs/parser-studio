import {describe,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import AutoParserAIReview from './AutoParserAIReview';

describe('AI recovery review safety',()=>{
 it('requires user-reviewed excerpt and request before copying whole log',()=>{
  render(<AutoParserAIReview raw="RAW event" status="unsupported" onChatGPT={vi.fn()}/>);
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
  fireEvent.change(screen.getByRole('textbox',{name:'AI correction request'}),{target:{value:'Extract source IP'}});
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
  fireEvent.change(screen.getByRole('textbox',{name:'Reviewed and redacted AI excerpt'}),{target:{value:'REDACTED event'}});
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(false);
 });
 it('does not authorize selected-area copy without exact selection',()=>{
  render(<AutoParserAIReview raw="src=192.0.2.1" status="partial" onChatGPT={vi.fn()}/>);
  fireEvent.change(screen.getByRole('textbox',{name:'AI correction request'}),{target:{value:'Extract IP'}});
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByRole('button',{name:'Copy AI Prompt'}).hasAttribute('disabled')).toBe(true);
 });
 it('rejects unverified AI recipe and never applies changes',()=>{
  render(<AutoParserAIReview raw="RAW" status="unsupported" onChatGPT={vi.fn()}/>);
  fireEvent.click(screen.getByText('Paste AI Recipe for strict review'));
  fireEvent.change(screen.getByRole('textbox',{name:'AI Recipe JSON'}),{target:{value:'{"code":"unsafe"}'}});
  expect(screen.getByRole('button',{name:'Validate Proposal (Review Only)'}).hasAttribute('disabled')).toBe(true);
 });
 it('opens the existing assisted parser path',()=>{
  const onChatGPT=vi.fn();
  render(<AutoParserAIReview raw="RAW" status="unsupported" onChatGPT={onChatGPT}/>);
  fireEvent.click(screen.getByRole('button',{name:'Open Assisted Parser'}));
  expect(onChatGPT).toHaveBeenCalledTimes(1);
 });
});
