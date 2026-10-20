/** Additional grammars are explicit; an absent profile retains V15 behavior. */
export const GENERIC_STRUCTURAL_SINGLE_PROFILES=['syslog_prefix_kv','leef2_implicit_tab'] as const;
export type GenericStructuralSingleProfile=(typeof GENERIC_STRUCTURAL_SINGLE_PROFILES)[number];
export const GENERIC_STRUCTURAL_MIXED_PROFILE_V1='syslog_prefix_kv_leef2_implicit_tab_v1' as const;
export const GENERIC_STRUCTURAL_PROFILES=[
  ...GENERIC_STRUCTURAL_SINGLE_PROFILES,GENERIC_STRUCTURAL_MIXED_PROFILE_V1,
] as const;
export type GenericStructuralProfile=(typeof GENERIC_STRUCTURAL_PROFILES)[number];

/** The original capability list stays readable by already loaded older clients. */
export function isGenericStructuralSingleProfile(value:unknown):value is GenericStructuralSingleProfile{
  return typeof value==='string'&&GENERIC_STRUCTURAL_SINGLE_PROFILES.some(profile=>profile===value);
}

export function isGenericStructuralProfile(value:unknown):value is GenericStructuralProfile{
  return typeof value==='string'&&GENERIC_STRUCTURAL_PROFILES.some(profile=>profile===value);
}
