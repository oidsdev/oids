// Stand-in for worker/legal.js so public-read tests can load the worker.
// Production legal copy is not part of this checkout; this file is test-only.
export const TERMS_BODY = '';
export const PRIVACY_BODY = '';
export const CONTENT_POLICY_BODY = '';

export function legalPage(title, body) {
  return `<!doctype html><title>${title}</title>${body}`;
}
