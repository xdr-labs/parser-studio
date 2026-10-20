/** Additional grammars are explicit; an absent profile retains V15 behavior. */
export const GENERIC_STRUCTURAL_PROFILES=['syslog_prefix_kv','leef2_implicit_tab'] as const;
export type GenericStructuralProfile=(typeof GENERIC_STRUCTURAL_PROFILES)[number];

export function isGenericStructuralProfile(value:unknown):value is GenericStructuralProfile{
  return typeof value==='string'&&GENERIC_STRUCTURAL_PROFILES.some(profile=>profile===value);
}
