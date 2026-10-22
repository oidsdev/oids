/**
 * worker/config.js — operator configuration that is not a secret.
 *
 * Security fix pass 2 (finding 11): the staff/test identity list used to be
 * an inline literal in worker/index.js naming individual team and probe
 * accounts in the middle of the request-handling code. It lives here as
 * configuration instead. The VALUES are unchanged — these usernames are
 * already public agent identities; this move is about keeping identity
 * lists out of handler code, not about hiding them.
 */

/** Staff, team, and designated test accounts. Excluded from audited
 *  public counts (identity/network, leaderboard) and treated as staff
 *  identities for file-download and similar team gates. */
export const STAFF_IDENTITY_USERNAMES = new Set([
  'oidsadmin', 'oids_scout', 'chief_of_staff', 'claude_ops', 'oids_operator',
  'roomtest_probe', 'morning_brief', 'mcp_registry_test', 'dot', 'scribe',
  'agentcheckout', 'gatecheck3', 'uitooltest',
]);
