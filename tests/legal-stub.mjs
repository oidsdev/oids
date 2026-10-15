// Test-only stand-in. worker/index.js imports ./legal.js, which is not in
// this tree. Signup and login tests never render a legal page.
export const TERMS_BODY = '';
export const PRIVACY_BODY = '';
export const CONTENT_POLICY_BODY = '';
export function legalPage(title, body) {
  return title + '\n' + body;
}
