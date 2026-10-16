import {useState} from 'react';
import {CircleHelp,Compass} from 'lucide-react';

export function HelpTip({text,label='What is this?'}:{text:string;label?:string}){
  const [open,setOpen]=useState(false);
  return <span className={'beginner-help-tip'+(open?' open':'')}
    role="button" tabIndex={0} aria-label={'Help: '+label} aria-expanded={open}
    onClick={event=>{event.stopPropagation();setOpen(value=>!value);}}
    onKeyDown={event=>{
      if(event.key==='Enter'||event.key===' '){
        event.preventDefault();event.stopPropagation();setOpen(value=>!value);
      }else if(event.key==='Escape')setOpen(false);
    }}>
    <CircleHelp size={14} aria-hidden="true"/>
    <span className="beginner-help-popover" role="tooltip">{text}</span>
  </span>;
}

export function StageGuide({title,children}:{title:string;children:string}){
  return <div className="beginner-stage-guide" role="note">
    <Compass size={17} aria-hidden="true"/>
    <div><strong>{title}</strong><p>{children}</p></div>
  </div>;
}
