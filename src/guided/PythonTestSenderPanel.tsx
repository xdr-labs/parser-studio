import {useState} from 'react';
import {Download} from 'lucide-react';
import type {ParserDraft} from '../model';
import {preparePythonTestSender} from './pythonTestSender';

interface Props{
  source:string;
  draft:ParserDraft;
}
export default function PythonTestSenderPanel({source,draft}:Props){
  const [error,setError]=useState('');
  const [status,setStatus]=useState('');
  const createDownload=()=>{
    setError('');setStatus('');
    try{
      const prepared=preparePythonTestSender(source,draft);
      const blob=new Blob([prepared.script],{type:'text/x-python;charset=utf-8'});
      const url=URL.createObjectURL(blob);
      const link=document.createElement('a');
      link.href=url;link.download=prepared.filename;
      document.body.append(link);link.click();link.remove();
      window.setTimeout(()=>URL.revokeObjectURL(url),1000);
      setStatus('Downloaded Python test sender for '+prepared.eventCount+
        ' current log sample event(s). Run it locally to enter the sensor IP and port. No log was transmitted by Parser Studio.');
    }catch(exc){
      setError(exc instanceof Error?exc.message:'The test sender could not be generated.');
    }
  };
  return <details className="auto-parser-recipe" aria-label="Python test sender">
    <summary className="beginner-tool-summary">Generate a Python Test Sender
      <small>Optional offline utility · no sensor connection from this browser</small>
    </summary>
    <p>Use the current log samples as a replay template. The script changes supported event
      timestamps and recognized IP, user, email and location fields each time it sends a record,
      preserving supported log grammar. It sends at most one event per second.</p>
    <p className="auto-parser-warning" role="note">
      The downloaded Python file contains your sample logs encoded as base64, not encrypted.
      Review or mask sensitive values before sharing it. Unknown or ambiguous fields may remain
      unchanged. Downloading alone never connects to a sensor.
    </p>
    <p>Run the script with Python 3 on a computer you control. It asks for the target sensor IP
      address, destination port, UDP or TCP transport, and event count before sending.
      You must confirm by typing YES. Default: 60 events, one per second. Ctrl-C stops it.</p>
    <p>No pip, third-party module, account credential, DP API, ingest-result check or
      Parser Studio server-side log sender is required. Only test targets you are authorized to use.</p>
    <button type="button" disabled={!source.trim()} onClick={createDownload}
      aria-label="Download Python Test Sender">
      <Download size={16}/> Download Python Test Sender (.py)
    </button>
    {error&&<p role="alert">{error}</p>}
    {status&&<p role="status">{status}</p>}
  </details>;
}
