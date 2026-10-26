import type {Dispatch,SetStateAction} from 'react';
import type {ParserDraft} from '../model';
import {DEFAULT_PARSER_LISTENER_PORT,defaultGuidedOptions} from './contract';
import {parserIdentitySlug} from './parserIdentity';
import ParserListenerPortInput from './ParserListenerPortInput';

interface Props {
  draft:ParserDraft;
  setDraft:Dispatch<SetStateAction<ParserDraft>>;
  /** ChatGPT receives only the manually copied metadata hints, never the port. */
  assisted?:boolean;
}

/** Shared identity and export-port controls for both parser creation paths. */
export default function ParserIdentityCard({draft,setDraft,assisted=false}:Props){
  const parserIdentityIsDefault=draft.vendor==='Demo / local draft'&&
    draft.name==='Untitled parser';
  const artifactName=parserIdentityIsDefault
    ?'customized_<manufacturer>_<product>'
    :'customized_'+(draft.guided?.slug??parserIdentitySlug(draft.vendor,draft.name));
  const updateIdentity=(field:'vendor'|'name'|'version',value:string)=>{
    setDraft(old=>{
      const vendor=field==='vendor'?value:old.vendor;
      const name=field==='name'?value:old.name;
      const version=field==='version'?value:(old.version??'');
      const guided=old.guided??defaultGuidedOptions();
      return {...old,vendor,name,version,
        guided:{...guided,slug:parserIdentitySlug(vendor,name)}};
    });
  };
  return <div className="parser-identity-card" aria-label="Parser product identity">
    <div className="parser-identity-copy">
      <strong>Parser details for the downloadable files</strong>
      <span>{assisted
        ?'Use the same manufacturer, product, version and receiving port as Auto Parser. Manufacturer, product and version are unverified hints included only when you manually copy the ChatGPT prompt; the port configures the generated .conf.'
        :'Set the manufacturer, product and receiving port before downloading parser files. These details do not affect log detection.'}</span>
    </div>
    <div className="parser-identity-fields">
      <label>Manufacturer
        <input aria-label="Parser manufacturer" value={draft.vendor}
          placeholder="e.g. Fortinet"
          onChange={e=>updateIdentity('vendor',e.target.value)}/>
      </label>
      <label>Product
        <input aria-label="Parser product" value={draft.name}
          placeholder="e.g. FortiGate"
          onChange={e=>updateIdentity('name',e.target.value)}/>
      </label>
      <label>Version
        <input aria-label="Parser product version" value={draft.version??''}
          placeholder="e.g. 7.4.5"
          onChange={e=>updateIdentity('version',e.target.value)}/>
      </label>
      <ParserListenerPortInput draft={draft} setDraft={setDraft}/>
    </div>
    <div className="parser-identity-filename">
      <span>Generated parser files</span>
      <code>{artifactName}</code>
      <code>{artifactName}.conf</code>
      <small>Generated .conf receiving port: {draft.guided?.receiver.port??DEFAULT_PARSER_LISTENER_PORT}</small>
      <small>Stellar custom parsers use the <b>customized_&lt;vendor&gt;_&lt;product&gt;</b> naming convention. Version is stored in the parser metadata rather than appended to the file name.</small>
    </div>
  </div>;
}
