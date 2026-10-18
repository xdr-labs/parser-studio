/** Maps stable server JSON pointers to the existing no-code correction stages. */
export function backendIssueTarget(path: string): { step: number; label: string } {
  if (path === '/slug' || path === '/vendor' || path === '/product' ||
      path === '/sourceCategory' || path.startsWith('/projectId')) {
    return { step: 0, label: 'Go to Parser Details' };
  }
  if (path === '/extraction' || path.startsWith('/extraction/')) {
    return { step: 1, label: 'Go to Extraction Settings' };
  }
  if (path === '/normalization' || path.startsWith('/normalization/') ||
      path === '/mappings' || path.startsWith('/mappings/')) {
    return { step: 2, label: 'Go to Mapping' };
  }
  if (path === '/receiver' || path.startsWith('/receiver/')) {
    return { step: 3, label: 'Go to Receiver Settings' };
  }
  if (path === '/classification' || path.startsWith('/classification/')) {
    return { step: 3, label: 'Go to Classification Settings' };
  }
  return { step: 5, label: 'Review Validation Details' };
}
