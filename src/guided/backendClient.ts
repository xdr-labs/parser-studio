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
    throw new Error('파서 백엔드가 유효한 JSON을 반환하지 않았습니다. 연결 상태를 확인하세요.');
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
  if (!payload || typeof payload !== 'object') throw new Error('백엔드 검증 응답 형식이 잘못되었습니다.');
  const check = payload as Partial<BackendValidationResult>;
  if (typeof check.ok !== 'boolean' || !isIssueList(check.issues)) {
    throw new Error('백엔드 검증 응답에 필수 항목이 없습니다.');
  }
  if (status !== 200 && status !== 422) throw new Error('파서 백엔드 검증 요청이 실패했습니다 (HTTP ' + status + ').');
  if ((status === 422 && check.ok) || (status === 200 && !check.ok)) throw new Error('백엔드 응답 상태가 서로 일치하지 않습니다.');
  return { ok: check.ok, issues: check.issues };
}

async function digestSHA256(content: string): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error('파일 해시 검증에는 보안 연결(HTTPS 또는 localhost)이 필요합니다.');
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
    throw new Error('백엔드 파일 생성 요청에 실패했습니다 (HTTP ' + status + ').');
  }
  if (!payload || typeof payload !== 'object') throw new Error('파일 생성 응답이 유효하지 않습니다.');
  const result = payload as Partial<GeneratedPair>;
  const expectedNames = ['customized_' + project.slug + '.conf', 'customized_' + project.slug];
  if (result.contract !== 'host-customized-pair.v0.1' || !Array.isArray(result.files) || result.files.length !== 2) {
    throw new Error('지원하지 않는 파서 생성 형식 또는 파일 개수입니다.');
  }
  if (!result.manifest || result.manifest.status !== 'DRAFT' ||
      result.manifest.contract !== result.contract || result.manifest.schemaRevision !== '0.1' ||
      result.manifest.engineVerified !== false || result.manifest.targetImportVerified !== false ||
      !Array.isArray(result.manifest.warnings) || !result.manifest.warnings.every((item) => typeof item === 'string') ||
      !result.manifest.fileHashes || typeof result.manifest.fileHashes !== 'object') {
    throw new Error('생성 매니페스트의 검증 상태가 지원 계약과 다릅니다.');
  }
  for (const [i, file] of result.files.entries()) {
    if (file.name !== expectedNames[i] || typeof file.content !== 'string' ||
        !Number.isInteger(file.bytes) || file.bytes < 1 || file.bytes > MAX_ARTIFACT_BYTES ||
        !/^[a-f0-9]{64}$/.test(file.sha256)) {
      throw new Error('생성 파일의 이름, 크기 또는 해시 형식이 잘못되었습니다.');
    }
    if (new TextEncoder().encode(file.content).length !== file.bytes ||
        await digestSHA256(file.content) !== file.sha256 ||
        result.manifest.fileHashes[file.name] !== file.sha256) {
      throw new Error('다운로드 전 파일 무결성 SHA-256 검증에 실패했습니다.');
    }
  }
  return result as GeneratedPair;
}
