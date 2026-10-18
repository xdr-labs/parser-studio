import type { BackendParserProject } from './backendAdapter';

export interface BackendIssue {
  code: string;
  path: string;
  message: string;
}
export interface BackendValidationResult {
  ok: boolean;
  issues: BackendIssue[];
}
export interface GeneratedPairFile {
  name: string;
  content: string;
  sha256: string;
  bytes: number;
}
export interface GeneratedPair {
  contract: 'host-customized-pair.v0.1';
  files: GeneratedPairFile[];
  manifest: {
    status: 'DRAFT';
    contract: 'host-customized-pair.v0.1';
    schemaRevision: '0.1';
    /** Populated by the reviewed compiler; required by ZIP packaging. */
    projectId?: string;
    projectRevision?: number;
    fileHashes: Record<string, string>;
    engineVerified: false;
    targetImportVerified: false;
    warnings: string[];
  };
}

const BASE = '/api/v1/parser-pairs';
const MAX_ARTIFACT_BYTES = 512 * 1024;

async function postProject(
  operation: 'validate' | 'generate',
  project: BackendParserProject,
  requester: typeof fetch,
): Promise<{ status: number; payload: unknown }> {
  const response = await requester(BASE + '/' + operation, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    cache: 'no-store',
    credentials: 'same-origin',
    body: JSON.stringify(project),
  });
  let payload: unknown;
  try { payload = await response.json(); } catch {
    throw new Error('The parser backend returned invalid JSON. Check connectivity.');
  }
  return { status: response.status, payload };
}

function isIssueList(input: unknown): input is BackendIssue[] {
  return Array.isArray(input) && input.every((value) =>
    value && typeof value === 'object' &&
    typeof value.code === 'string' && typeof value.path === 'string' &&
    typeof value.message === 'string');
}

export async function validateBackendProject(
  project: BackendParserProject,
  requester: typeof fetch = fetch,
): Promise<BackendValidationResult> {
  const { status, payload } = await postProject('validate', project, requester);
  if (!payload || typeof payload !== 'object') throw new Error('Invalid backend validation response format.');
  const check = payload as Partial<BackendValidationResult>;
  if (typeof check.ok !== 'boolean' || !isIssueList(check.issues)) {
    throw new Error('Backend validation response is missing required properties.');
  }
  if (status !== 200 && status !== 422) throw new Error('Parser backend validation failed (HTTP ' + status + ').');
  if ((status === 422 && check.ok) || (status === 200 && !check.ok)) throw new Error('Backend HTTP status conflicts with its reported validation status.');
  return { ok: check.ok, issues: check.issues };
}

async function digestSHA256(content: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error('File hash verification requires HTTPS or localhost.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
  return [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, '0')).join('');
}

export async function generateBackendPair(
  project: BackendParserProject,
  requester: typeof fetch = fetch,
): Promise<GeneratedPair> {
  const { status, payload } = await postProject('generate', project, requester);
  if (status !== 200) {
    const error = payload as Partial<BackendValidationResult>;
    if (error?.issues && isIssueList(error.issues)) {
      throw new Error(error.issues.map((item) => item.code + ': ' + item.message).join(' · '));
    }
    throw new Error('Backend parser-pair generation failed (HTTP ' + status + ').');
  }
  if (!payload || typeof payload !== 'object') throw new Error('Parser-pair generation response is invalid.');
  const result = payload as Partial<GeneratedPair>;
  const expectedNames = ['customized_' + project.slug + '.conf', 'customized_' + project.slug];
  if (result.contract !== 'host-customized-pair.v0.1' || !Array.isArray(result.files) || result.files.length !== 2) {
    throw new Error('Unsupported parser-pair format or number of generated files.');
  }
  if (!result.manifest || result.manifest.status !== 'DRAFT' ||
      result.manifest.contract !== result.contract || result.manifest.schemaRevision !== '0.1' ||
      result.manifest.engineVerified !== false || result.manifest.targetImportVerified !== false ||
      !Array.isArray(result.manifest.warnings) || !result.manifest.warnings.every((item) => typeof item === 'string') ||
      !result.manifest.fileHashes || typeof result.manifest.fileHashes !== 'object') {
    throw new Error('Generated manifest verification status violates the supported contract.');
  }
  for (const [i, file] of result.files.entries()) {
    if (file.name !== expectedNames[i] || typeof file.content !== 'string' ||
        !Number.isInteger(file.bytes) || file.bytes < 1 || file.bytes > MAX_ARTIFACT_BYTES ||
        !/^[a-f0-9]{64}$/.test(file.sha256)) {
      throw new Error('Generated filename, size, or hash format is invalid.');
    }
    if (new TextEncoder().encode(file.content).length !== file.bytes ||
        await digestSHA256(file.content) !== file.sha256 ||
        result.manifest.fileHashes[file.name] !== file.sha256) {
      throw new Error('Pre-download SHA-256 integrity verification failed.');
    }
  }
  return result as GeneratedPair;
}
