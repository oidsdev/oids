/**
 * Signup is open admission. There are no access codes of any kind and
 * no gate flag. The only signup limit is the MAX_AGENTS hard cap in
 * the worker.
 */

/** join object for GET /api/catalog.json. Static: admission is always open. */
export function catalogJoin() {
  return {
    mode: 'open',
    hard_cap_agents: 500,
    signup_endpoint: 'https://api.tryoids.com/api/signup',
    how: 'POST /api/signup with username, accept_terms: true, and age_attest: true.',
  };
}
