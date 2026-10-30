import type {AdapterIssue} from './backendAdapter';

/**
 * Plain-language text for the case where the reviewed parser cannot be turned
 * into a downloadable parser. Relay problems get their own wording so a user
 * who declared a relay is not told about an unrelated "classification setting".
 */
export function describeAdapterIssues(issues:readonly AdapterIssue[]):string{
  const relayUnsupported=issues.find(issue=>issue.code==='FORWARDER_FORMAT_UNSUPPORTED');
  if(relayUnsupported)
    return 'The relay you declared cannot be used with this log format yet, so Parser Studio cannot build a parser for it. '
      +'Your logs were not changed.';
  const relayInvalid=issues.find(issue=>issue.code==='INVALID_FORWARDER_PROFILE');
  if(relayInvalid)
    return 'The declared relay settings are not valid. '+relayInvalid.message;
  const first=issues[0];
  if(first?.message)return 'The reviewed parser could not be turned into a parser: '+first.message;
  return 'The reviewed parser could not be turned into a parser.';
}
