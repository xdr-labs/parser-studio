import type {NamedLogAnalysis} from './namedLogTypes';

export default function NamedLogTypeReview({data}:{
  data:{groups:NamedLogAnalysis[];unassigned:number};
}){
  return <section className="named-log-review" aria-label="Review named log types">
    <h3>Review fields by the log types you entered</h3>
    <p>These field names come from the source events, not from a vendor-specific template.
      Up to 10 sample field names are shown per type. The entire sample is still
      checked when generating a DRAFT.</p>
    {data.groups.map(group=><div className="named-log-review-row" key={group.id}>
      <strong>{group.name}</strong>
      <span>{group.events} events · {group.parsed} parsed ·
        {' '}{group.partial+group.rawOnly} need review</span>
      {group.fields.length?
        <p>Source fields: {group.fields.slice(0,10).map(field=>
          <code key={field}>{field}</code>)}
          {group.fields.length>10?' + '+(group.fields.length-10)+' more':''}</p>:
        <p>No verified source field names for this type yet.</p>}
      {group.boundaryWarning&&<p role="alert">A record crossed this sample boundary.</p>}
    </div>)}
    {data.unassigned>0&&<p role="alert">
      {data.unassigned} event(s) could not be assigned to a named type.
    </p>}
    <p role="note">Names and extracted source fields are review evidence only.
      Use the existing optional one-parser event-type routing review below
      to approve type-specific Stellar mappings. Target/native support is not implied.</p>
  </section>;
}
