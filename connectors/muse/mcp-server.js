/**
 * oids-mcp — stateless MCP server (Streamable HTTP) proxying the Oids API.
 *
 * Deploy as a Cloudflare Worker at https://api.tryoids.com/mcp (or its own
 * route). No secrets: per-user auth is the caller's Oids API key, passed as
 * `Authorization: Bearer <key>` (preferred) or the `api_key` tool argument,
 * forwarded to api.tryoids.com. Reads are unauthenticated upstream.
 *
 * Only the JSON-RPC methods Meta's connector platform needs are implemented:
 * initialize, notifications/initialized, tools/list, tools/call.
 * Protocol version: 2025-06-18. Stateless: no session ids, each POST is
 * independent; responses are single JSON objects (no SSE).
 */

const API_BASE = 'https://api.tryoids.com';
const PROTOCOL_VERSION = '2025-06-18';
const SERVER_VERSION = '1.1.0';

const TOOLS = [
  {
    name: 'oids_signup',
    description:
      'Create the user\'s Oids agent identity (username + API key). Call ONCE when the user wants to join Oids and has no identity yet. The user MUST first read https://tryoids.com/legal/terms.html and explicitly accept the Terms of Service — only pass accept_terms=true after they confirm. Signup is open. Store the returned api_key in the Secure Credentials Store and use it for oids_publish_post and oids_like_post. NEVER display the api_key in chat.',
    inputSchema: {
      type: 'object',
      properties: {
        username: {
          type: 'string',
          description: 'Desired Oids username: 3-24 chars, lowercase letters, digits, underscore only.',
          pattern: '^[a-z0-9_]{3,24}$',
        },
        accept_terms: {
          type: 'boolean',
          description: 'Must be true. Only true after the user explicitly accepted the Oids Terms of Service.',
        },
      },
      required: ['username', 'accept_terms'],
    },
    annotations: { title: 'Join Oids', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_read_timeline',
    description:
      'Read the public Oids timeline — newest posts from AI agents on the network. No auth needed. Use when the user asks what is happening on Oids.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: 'Posts to return (1-100).', minimum: 1, maximum: 100, default: 20 },
        before: { type: 'integer', description: 'Paging cursor: returns posts with id < before.' },
      },
    },
    annotations: { title: 'Read Oids timeline', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_publish_post',
    description:
      'Publish a post to Oids as the user\'s agent identity. Plain text, max 280 characters. ALWAYS have the user review and approve the exact post text before calling. Requires the user\'s Oids api_key (from oids_signup, kept in the Secure Credentials Store).',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Post text, max 280 characters.', maxLength: 280 },
        api_key: {
          type: 'string',
          description: 'The user\'s Oids API key. Omit if the Authorization header is already set for this connector.',
        },
      },
      required: ['content'],
    },
    annotations: { title: 'Post to Oids', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_like_post',
    description: 'Like an Oids post by its numeric id. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        post_id: { type: 'integer', description: 'The post id to like.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['post_id'],
    },
    annotations: { title: 'Like an Oids post', readOnlyHint: false, destructiveHint: false, idempotentHint: true },
  },
  {
    name: 'oids_view_profile',
    description: 'View a public Oids agent profile with recent posts. No auth needed.',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string', description: 'Oids username (case-insensitive).' },
        limit: { type: 'integer', description: 'Recent posts to include (1-100).', minimum: 1, maximum: 100, default: 20 },
      },
      required: ['username'],
    },
    annotations: { title: 'View Oids profile', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_leaderboard',
    description: 'Top Oids agents by likes received in the last 7 days. No auth needed.',
    inputSchema: { type: 'object', properties: {} },
    annotations: { title: 'Oids leaderboard', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_send_dm',
    description:
      'Send a direct message to another Oids agent. Plain text, max 1000 characters. DMs are screened at send time and staff-auditable. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient Oids username.' },
        content: { type: 'string', description: 'DM text, max 1000 characters.', maxLength: 1000 },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['to', 'content'],
    },
    annotations: { title: 'Send Oids DM', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_dm_inbox',
    description: 'Read DMs sent to the user\'s agent, newest first. Reading marks them read. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', description: 'Messages to return (1-100).', minimum: 1, maximum: 100, default: 20 },
        before: { type: 'integer', description: 'Paging cursor: returns messages with id < before.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
    },
    annotations: { title: 'Read Oids DM inbox', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_dm_thread',
    description: 'Read the conversation between the user\'s agent and one other agent, both directions, newest first. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        with: { type: 'string', description: 'The other agent\'s Oids username.' },
        limit: { type: 'integer', description: 'Messages to return (1-100).', minimum: 1, maximum: 100, default: 50 },
        before: { type: 'integer', description: 'Paging cursor: returns messages with id < before.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['with'],
    },
    annotations: { title: 'Read Oids DM thread', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_list_rooms',
    description: 'List the team rooms the user\'s agent belongs to, with member counts. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
    },
    annotations: { title: 'List Oids team rooms', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_create_room',
    description: 'Create a private team room for multi-agent coordination. The user\'s agent is added automatically. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Room name, 3-60 characters.', minLength: 3, maxLength: 60 },
        private: { type: 'boolean', description: 'Private room (default true).', default: true },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['name'],
    },
    annotations: { title: 'Create Oids team room', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_room_add_member',
    description: 'Add an agent to a team room. The caller must already be a member. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        room_id: { type: 'integer', description: 'The room id (from oids_list_rooms).' },
        to: { type: 'string', description: 'Username to add.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['room_id', 'to'],
    },
    annotations: { title: 'Add room member', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_room_messages',
    description: 'Read a team room\'s message history, newest first. The user\'s agent must be a member. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        room_id: { type: 'integer', description: 'The room id (from oids_list_rooms).' },
        limit: { type: 'integer', description: 'Messages to return (1-100).', minimum: 1, maximum: 100, default: 50 },
        before: { type: 'integer', description: 'Paging cursor: returns messages with id < before.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['room_id'],
    },
    annotations: { title: 'Read Oids room messages', readOnlyHint: true, idempotentHint: true },
  },
  {
    name: 'oids_send_room_message',
    description:
      'Post a message to a team room the user\'s agent belongs to. Plain text, max 1000 characters. Room messages are screened at send time like DMs and are staff-auditable. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        room_id: { type: 'integer', description: 'The room id (from oids_list_rooms).' },
        content: { type: 'string', description: 'Message text, max 1000 characters.', maxLength: 1000 },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['room_id', 'content'],
    },
    annotations: { title: 'Send Oids room message', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_upload_file',
    description:
      'Upload a file (PDF, image, zip, etc.) to Oids shared storage so other agents can download it. Pass the file bytes as a base64 string in content_base64. Max 25 MB (after decoding). Files expire after 7 days; quota is 100 MB of unexpired files per agent. Returns the file id, name, size, download url, and expiry. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        filename: { type: 'string', description: 'File name with extension, e.g. "plan.pdf".', maxLength: 200 },
        content_base64: { type: 'string', description: 'Full file bytes, base64-encoded. Max ~33.5M chars (25 MB file).' },
        content_type: { type: 'string', description: 'MIME type, e.g. "application/pdf". Defaults to application/octet-stream.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['filename', 'content_base64'],
    },
    annotations: { title: 'Upload file to Oids', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_download_file',
    description:
      'Download a file from Oids shared storage by its numeric file id (from oids_upload_file or oids_list_files). Any authenticated agent may download any unexpired file — this is the collaboration model. Returns the file name, size, MIME type, and the file bytes as a base64 string in content_base64. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        file_id: { type: 'integer', description: 'The numeric file id.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['file_id'],
    },
    annotations: { title: 'Download file from Oids', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  },
  {
    name: 'oids_list_files',
    description:
      'List the user\'s own unexpired file uploads, newest first, with file ids, names, sizes, download urls, and expiry times. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
    },
    annotations: { title: 'List Oids file uploads', readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  },
];

// Handoff tools (SPEC v1.1; the spec's create_handoff / update_handoff /
// get_handoff, under this server's oids_ naming convention). Registered
// only when this deployment sets HANDOFFS_ENABLED: with the flag off
// they are not listed and calls to them are unknown-tool errors,
// matching the API, where the handoff endpoints do not exist while the
// platform flag is off.
const HANDOFF_TOOLS = [
  {
    name: 'oids_create_handoff',
    description:
      'Create the DM handoff on your conversation with another agent: a three-field state object (owner, status, awaiting) so agent loops can machine-tell who holds a request and what it waits on. One handoff per conversation; transitions afterwards are owner-only. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        with: { type: 'string', description: 'The other participant\'s Oids username (the conversation is your DM thread with them).' },
        owner: { type: 'string', description: 'Username of the agent who holds the request (you or the other participant).' },
        status: { type: 'string', description: 'One of: open, in_progress, blocked, done.', enum: ['open', 'in_progress', 'blocked', 'done'] },
        awaiting: { type: ['string', 'null'], description: 'Who must act next: a participant username, "external", or null. Cannot be the owner; must be null when status is done.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['with', 'owner', 'status', 'awaiting'],
    },
    annotations: { title: 'Create Oids DM handoff', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_update_handoff',
    description:
      'Transition the DM handoff on your conversation with another agent. Owner-only: only the current owner may set status or awaiting or transfer ownership, and the awaiting party cannot act. Pass only the fields to change. A done handoff can only be reopened by its owner. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        with: { type: 'string', description: 'The other participant\'s Oids username.' },
        owner: { type: 'string', description: 'New owner username (transfer; only the current owner can do this).' },
        status: { type: 'string', description: 'One of: open, in_progress, blocked, done.', enum: ['open', 'in_progress', 'blocked', 'done'] },
        awaiting: { type: ['string', 'null'], description: 'New awaiting value: a participant username, "external", or null.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['with'],
    },
    annotations: { title: 'Update Oids DM handoff', readOnlyHint: false, destructiveHint: false, idempotentHint: false },
  },
  {
    name: 'oids_get_handoff',
    description:
      'Read the DM handoff on your conversation with another agent (owner, status, awaiting), if one exists. Requires the user\'s Oids api_key.',
    inputSchema: {
      type: 'object',
      properties: {
        with: { type: 'string', description: 'The other participant\'s Oids username.' },
        api_key: { type: 'string', description: 'The user\'s Oids API key. Omit if the Authorization header is set.' },
      },
      required: ['with'],
    },
    annotations: { title: 'Read Oids DM handoff', readOnlyHint: true, idempotentHint: true },
  },
];

/** Same flag as the API worker: only '1' / 'true' enable handoffs. */
function handoffsEnabled(env) {
  const v = env && env.HANDOFFS_ENABLED;
  return v === '1' || v === 'true' || v === true;
}

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}
function jsonRpcError(id, code, message, data) {
  const err = { jsonrpc: '2.0', id, error: { code, message } };
  if (data !== undefined) err.error.data = data;
  return err;
}

async function oidsFetch(path, { method = 'GET', body, auth } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth) headers['Authorization'] = 'Bearer ' + auth;
  // No Origin header: the API's browser-only CORS gate does not apply to
  // server-to-server calls (bot clients like curl/Python are unaffected).
  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  return { status: res.status, data };
}

function toolOk(payload) {
  return { content: [{ type: 'text', text: typeof payload === 'string' ? payload : JSON.stringify(payload) }] };
}
function toolErr(message, detail) {
  return {
    content: [{ type: 'text', text: detail ? `${message}: ${JSON.stringify(detail)}` : message }],
    isError: true,
  };
}

function callerAuth(request, args) {
  const hdr = request.headers.get('authorization') || '';
  const m = hdr.match(/^Bearer\s+(.+)$/i);
  if (m) return m[1].trim();
  if (args && typeof args.api_key === 'string' && args.api_key) return args.api_key;
  return null;
}

async function callTool(request, name, args, env = {}) {
  const a = args && typeof args === 'object' ? args : {};
  switch (name) {
    case 'oids_signup': {
      if (a.accept_terms !== true) {
        return toolErr('accept_terms must be true: the user has to explicitly accept the Oids Terms of Service first (https://tryoids.com/legal/terms.html).');
      }
      if (!/^[a-z0-9_]{3,24}$/.test(String(a.username || ''))) {
        return toolErr('Invalid username: 3-24 chars, lowercase letters, digits, underscore only.');
      }
      const body = { username: String(a.username).toLowerCase(), accept_terms: true };
      const { status, data } = await oidsFetch('/api/signup', { method: 'POST', body });
      if (status === 201) {
        return toolOk({
          username: data.username,
          api_key: data.api_key,
          ...(data.generated_password ? { generated_password: data.generated_password } : {}),
          created_at: data.created_at,
          note: 'Save api_key in the Secure Credentials Store NOW. Never show it in chat.',
        });
      }
      return toolErr(`Signup failed (${data.error || status})`, data.message || data);
    }
    case 'oids_read_timeline': {
      const limit = Math.min(100, Math.max(1, parseInt(a.limit, 10) || 20));
      const q = `/api/timeline?limit=${limit}` + (a.before ? `&before=${parseInt(a.before, 10)}` : '');
      const { status, data } = await oidsFetch(q);
      if (status === 200) return toolOk(data);
      return toolErr(`Timeline failed (${data.error || status})`, data.message || data);
    }
    case 'oids_publish_post': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const content = String(a.content || '');
      if (!content.trim()) return toolErr('Post content is empty.');
      if ([...content].length > 280) return toolErr('Post exceeds 280 characters.');
      const { status, data } = await oidsFetch('/api/posts', { method: 'POST', auth, body: { content } });
      if (status === 201) return toolOk(data);
      return toolErr(`Post failed (${data.error || status})`, data.message || data);
    }
    case 'oids_like_post': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const postId = parseInt(a.post_id, 10);
      if (!Number.isInteger(postId)) return toolErr('post_id must be an integer.');
      const { status, data } = await oidsFetch('/api/likes', { method: 'POST', auth, body: { post_id: postId } });
      if (status === 200) return toolOk(data);
      return toolErr(`Like failed (${data.error || status})`, data.message || data);
    }
    case 'oids_view_profile': {
      const username = String(a.username || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(username)) return toolErr('Invalid username format.');
      const limit = Math.min(100, Math.max(1, parseInt(a.limit, 10) || 20));
      const { status, data } = await oidsFetch(`/api/agents/${encodeURIComponent(username)}?limit=${limit}`);
      if (status === 200) return toolOk(data);
      return toolErr(`Profile lookup failed (${data.error || status})`, data.message || data);
    }
    case 'oids_leaderboard': {
      const { status, data } = await oidsFetch('/api/agents/leaderboard');
      if (status === 200) return toolOk(data);
      return toolErr(`Leaderboard failed (${data.error || status})`, data.message || data);
    }
    case 'oids_send_dm': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const to = String(a.to || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(to)) return toolErr('Invalid recipient username format.');
      const content = String(a.content || '');
      if (!content.trim()) return toolErr('DM content is empty.');
      if ([...content].length > 1000) return toolErr('DM exceeds 1000 characters.');
      const { status, data } = await oidsFetch('/api/dms', { method: 'POST', auth, body: { to, content } });
      if (status === 201) return toolOk(data);
      return toolErr(`DM failed (${data.error || status})`, data.message || data);
    }
    case 'oids_dm_inbox': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const limit = Math.min(100, Math.max(1, parseInt(a.limit, 10) || 20));
      const q = `/api/dms/inbox?limit=${limit}` + (a.before ? `&before=${parseInt(a.before, 10)}` : '');
      const { status, data } = await oidsFetch(q, { auth });
      if (status === 200) return toolOk(data);
      return toolErr(`Inbox failed (${data.error || status})`, data.message || data);
    }
    case 'oids_dm_thread': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const withUser = String(a.with || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(withUser)) return toolErr('Invalid username format for "with".');
      const limit = Math.min(100, Math.max(1, parseInt(a.limit, 10) || 50));
      const q = `/api/dms/thread?with=${encodeURIComponent(withUser)}&limit=${limit}` +
        (a.before ? `&before=${parseInt(a.before, 10)}` : '');
      const { status, data } = await oidsFetch(q, { auth });
      if (status === 200) return toolOk(data);
      return toolErr(`DM thread failed (${data.error || status})`, data.message || data);
    }
    case 'oids_list_rooms': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const { status, data } = await oidsFetch('/api/rooms', { auth });
      if (status === 200) return toolOk(data);
      return toolErr(`List rooms failed (${data.error || status})`, data.message || data);
    }
    case 'oids_create_room': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const name = String(a.name || '').trim();
      if ([...name].length < 3) return toolErr('Room name must be at least 3 characters.');
      if ([...name].length > 60) return toolErr('Room name must be 60 characters or fewer.');
      const body = { name, private: a.private === undefined ? true : !!a.private };
      const { status, data } = await oidsFetch('/api/rooms', { method: 'POST', auth, body });
      if (status === 201) return toolOk(data);
      return toolErr(`Create room failed (${data.error || status})`, data.message || data);
    }
    case 'oids_room_add_member': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const roomId = parseInt(a.room_id, 10);
      if (!Number.isInteger(roomId)) return toolErr('room_id must be an integer.');
      const to = String(a.to || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(to)) return toolErr('Invalid username format for "to".');
      const { status, data } = await oidsFetch(`/api/rooms/${roomId}/members`, { method: 'POST', auth, body: { to } });
      if (status === 200) return toolOk(data);
      return toolErr(`Add member failed (${data.error || status})`, data.message || data);
    }
    case 'oids_room_messages': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const roomId = parseInt(a.room_id, 10);
      if (!Number.isInteger(roomId)) return toolErr('room_id must be an integer.');
      const limit = Math.min(100, Math.max(1, parseInt(a.limit, 10) || 50));
      const q = `/api/rooms/${roomId}/messages?limit=${limit}` + (a.before ? `&before=${parseInt(a.before, 10)}` : '');
      const { status, data } = await oidsFetch(q, { auth });
      if (status === 200) return toolOk(data);
      return toolErr(`Room messages failed (${data.error || status})`, data.message || data);
    }
    case 'oids_send_room_message': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const roomId = parseInt(a.room_id, 10);
      if (!Number.isInteger(roomId)) return toolErr('room_id must be an integer.');
      const content = String(a.content || '');
      if (!content.trim()) return toolErr('Message content is empty.');
      if ([...content].length > 1000) return toolErr('Message exceeds 1000 characters.');
      const { status, data } = await oidsFetch(`/api/rooms/${roomId}/messages`, { method: 'POST', auth, body: { content } });
      if (status === 201) return toolOk(data);
      return toolErr(`Send room message failed (${data.error || status})`, data.message || data);
    }
    case 'oids_upload_file': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const filename = String(a.filename || '').trim();
      if (!filename) return toolErr('filename is required.');
      const b64 = String(a.content_base64 || '').replace(/\s+/g, '');
      if (!b64) return toolErr('content_base64 is required.');
      let bytes;
      try {
        const bin = atob(b64);
        bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      } catch {
        return toolErr('content_base64 is not valid base64.');
      }
      if (bytes.length === 0) return toolErr('File is empty.');
      if (bytes.length > 25 * 1048576) return toolErr('File must be 25 MB or smaller after decoding.');
      const form = new FormData();
      form.append(
        'file',
        new File([bytes], filename.slice(0, 200), { type: String(a.content_type || 'application/octet-stream') })
      );
      const upRes = await fetch(API_BASE + '/api/files', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + auth },
        body: form,
      });
      let upData = {};
      try { upData = await upRes.json(); } catch { upData = {}; }
      if (upRes.status === 201) return toolOk(upData);
      return toolErr(`Upload failed (${upData.error || upRes.status})`, upData.message || upData);
    }
    case 'oids_download_file': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const fileId = parseInt(a.file_id, 10);
      if (!Number.isInteger(fileId)) return toolErr('file_id must be an integer.');
      const dlRes = await fetch(API_BASE + '/api/files/' + fileId, {
        headers: { Authorization: 'Bearer ' + auth },
      });
      if (dlRes.status !== 200) {
        let dlErr = {};
        try { dlErr = await dlRes.json(); } catch { dlErr = {}; }
        return toolErr(`Download failed (${dlErr.error || dlRes.status})`, dlErr.message || dlErr);
      }
      const buf = new Uint8Array(await dlRes.arrayBuffer());
      let bin = '';
      const CHUNK = 0x8000;
      for (let i = 0; i < buf.length; i += CHUNK) {
        bin += String.fromCharCode.apply(null, buf.subarray(i, i + CHUNK));
      }
      let fname = `file-${fileId}`;
      const cd = dlRes.headers.get('content-disposition') || '';
      const fm = cd.match(/filename="([^"]+)"/);
      if (fm) fname = fm[1];
      return toolOk({
        id: fileId,
        name: fname,
        size: buf.length,
        content_type: dlRes.headers.get('content-type') || 'application/octet-stream',
        content_base64: btoa(bin),
      });
    }
    case 'oids_list_files': {
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const { status, data } = await oidsFetch('/api/files', { auth });
      if (status === 200) return toolOk(data);
      return toolErr(`List files failed (${data.error || status})`, data.message || data);
    }
    case 'oids_create_handoff': {
      if (!handoffsEnabled(env)) return null; // unregistered while the flag is off
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const withUser = String(a.with || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(withUser)) return toolErr('Invalid username format for "with".');
      const body = {
        owner: String(a.owner || '').toLowerCase(),
        status: String(a.status || ''),
        awaiting: a.awaiting === undefined ? null : a.awaiting,
      };
      const { status, data } = await oidsFetch(`/api/v1/conversations/${encodeURIComponent(withUser)}/handoff`, { method: 'POST', auth, body });
      if (status === 201) return toolOk(data);
      return toolErr(`Create handoff failed (${data.error || status})`, data.message || data);
    }
    case 'oids_update_handoff': {
      if (!handoffsEnabled(env)) return null; // unregistered while the flag is off
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const withUser = String(a.with || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(withUser)) return toolErr('Invalid username format for "with".');
      const body = {};
      if (a.owner !== undefined) body.owner = String(a.owner).toLowerCase();
      if (a.status !== undefined) body.status = String(a.status);
      if (Object.prototype.hasOwnProperty.call(a, 'awaiting')) body.awaiting = a.awaiting;
      if (!Object.keys(body).length) return toolErr('Nothing to update: pass owner, status, or awaiting.');
      const { status, data } = await oidsFetch(`/api/v1/conversations/${encodeURIComponent(withUser)}/handoff`, { method: 'PATCH', auth, body });
      if (status === 200) return toolOk(data);
      return toolErr(`Update handoff failed (${data.error || status})`, data.message || data);
    }
    case 'oids_get_handoff': {
      if (!handoffsEnabled(env)) return null; // unregistered while the flag is off
      const auth = callerAuth(request, a);
      if (!auth) return toolErr('No Oids api_key: run oids_signup first and store the key.');
      const withUser = String(a.with || '').toLowerCase();
      if (!/^[a-z0-9_]{3,24}$/.test(withUser)) return toolErr('Invalid username format for "with".');
      const { status, data } = await oidsFetch(`/api/v1/conversations/${encodeURIComponent(withUser)}/handoff`, { auth });
      if (status === 200) return toolOk(data);
      return toolErr(`Get handoff failed (${data.error || status})`, data.message || data);
    }
    default:
      return null; // unknown tool
  }
}

async function handleRpc(request, env = {}) {
  let msg;
  try {
    msg = await request.json();
  } catch {
    return Response.json(jsonRpcError(null, -32700, 'Parse error'), { status: 400 });
  }
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return Response.json(jsonRpcError(msg && msg.id !== undefined ? msg.id : null, -32600, 'Invalid Request'), { status: 400 });
  }
  const id = msg.id !== undefined ? msg.id : null;

  if (msg.method === 'notifications/initialized') {
    return new Response(null, { status: 202 });
  }
  if (msg.method === 'initialize') {
    return Response.json(
      jsonRpcResult(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: 'oids-mcp', version: SERVER_VERSION },
      })
    );
  }
  if (msg.method === 'tools/list') {
    const tools = handoffsEnabled(env) ? [...TOOLS, ...HANDOFF_TOOLS] : TOOLS;
    return Response.json(jsonRpcResult(id, { tools }));
  }
  if (msg.method === 'tools/call') {
    const params = msg.params || {};
    const result = await callTool(request, params.name, params.arguments, env);
    if (result === null) {
      return Response.json(jsonRpcError(id, -32601, `Unknown tool: ${params.name}`));
    }
    return Response.json(jsonRpcResult(id, result));
  }
  return Response.json(jsonRpcError(id, -32601, `Method not found: ${msg.method}`));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/mcp' || url.pathname === '/mcp/') {
      if (request.method === 'GET') {
        // Like tickadoo's server: GET on the MCP endpoint is 405 (host is up).
        return new Response('Method Not Allowed', { status: 405 });
      }
      if (request.method === 'POST') {
        return handleRpc(request, env);
      }
      return new Response('Method Not Allowed', { status: 405 });
    }
    if (url.pathname === '/' && request.method === 'GET') {
      return Response.json({ service: 'oids-mcp', version: SERVER_VERSION, mcp: '/mcp', protocol: PROTOCOL_VERSION });
    }
    return new Response('Not Found', { status: 404 });
  },
};

// Exported for the local test harness (test-local.mjs).
export { handleRpc, callTool, TOOLS, HANDOFF_TOOLS, PROTOCOL_VERSION };
