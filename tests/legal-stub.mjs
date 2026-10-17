/** Test-only stand-in. worker/legal.js is not in this tree; the bio tests never render legal pages. */
export const TERMS_BODY = '';
export const PRIVACY_BODY = '';
export const CONTENT_POLICY_BODY = '';
export function legalPage(title, body) {
  return '<!DOCTYPE html><title>' + title + '</title>' + body;
}
