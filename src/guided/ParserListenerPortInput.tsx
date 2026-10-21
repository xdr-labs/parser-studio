import type {Dispatch,SetStateAction} from 'react';
import type {ParserDraft} from '../model';
import {DEFAULT_PARSER_LISTENER_PORT,defaultGuidedOptions} from './contract';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
}

/** One user-selected receiving port is shared by both creation methods and the compiled CONF. */
export default function ParserListenerPortInput({draft,setDraft}:Props){
  const minimum=['syslog_rfc3164','syslog_rfc5424','generic_structural'].includes(draft.format)||
    (draft.format==='mixed'&&draft.mixedFormats?.some(format=>
      format.startsWith('rfc5424_')||format.startsWith('rfc3164_')))?6800:1024;
  const port=draft.guided?.receiver.port??DEFAULT_PARSER_LISTENER_PORT;
  const valid=Number.isInteger(port)&&port>=minimum&&port<=65535;
  return <label>Parser listener port (.conf)
    <input aria-label="Parser listener port" type="number" min={minimum} max={65535} step={1}
      value={port} aria-invalid={!valid}
      onChange={event=>{
        const changed=Number(event.currentTarget.value);
        setDraft(old=>{
          const guided=old.guided??defaultGuidedOptions();
          return {...old,guided:{...guided,receiver:{...guided.receiver,port:changed}}};
        });
      }}/>
    <small>Default 6801. Shared sensor destination and generated .conf receiving port. Check availability before deployment.</small>
    {!valid&&<small role="alert">Enter an integer port from {minimum} to 65535 before creating parser files.</small>}
  </label>;
}
