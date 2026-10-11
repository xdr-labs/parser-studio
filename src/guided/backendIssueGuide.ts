/** Maps stable server JSON pointers to the existing no-code correction stages. */
export function backendIssueTarget(path: string): { step: number; label: string } {
  if (path === '/slug' || path === '/vendor' || path === '/product' ||
      path === '/sourceCategory' || path.startsWith('/projectId')) {
    return { step: 0, label: '기본 정보로 이동' };
  }
  if (path === '/extraction' || path.startsWith('/extraction/')) {
    return { step: 1, label: '추출 설정으로 이동' };
  }
  if (path === '/normalization' || path.startsWith('/normalization/') ||
      path === '/mappings' || path.startsWith('/mappings/')) {
    return { step: 2, label: '필드 매핑으로 이동' };
  }
  if (path === '/receiver' || path.startsWith('/receiver/')) {
    return { step: 3, label: '수신 설정으로 이동' };
  }
  if (path === '/classification' || path.startsWith('/classification/')) {
    return { step: 3, label: '분류 설정으로 이동' };
  }
  return { step: 5, label: '검증 내용 확인' };
}
