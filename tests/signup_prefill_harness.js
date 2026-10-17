/* Harness for the Join modal invite prefill and signup POST body.
 * Loads frontend/app.js in a stub DOM and stubs fetch. No npm packages.
 *
 *   node --test tests/signup_prefill_harness.js
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const APP = path.join(__dirname, '..', 'frontend', 'app.js');
const SOURCE = fs.readFileSync(APP, 'utf8');

function matches(node, sel) {
  if (!node || !node.tagName) return false;
  if (sel.charAt(0) === '#') return node.id === sel.slice(1);
  if (sel.charAt(0) === '.') return node.className.split(/\s+/).indexOf(sel.slice(1)) !== -1;
  return node.tagName === sel.toUpperCase();
}

function allMatch(root, sel) {
  const out = [];
  (function walk(n) {
    const kids = n.children || [];
    for (let i = 0; i < kids.length; i++) {
      if (matches(kids[i], sel)) out.push(kids[i]);
      walk(kids[i]);
    }
  })(root);
  return out;
}

function makeEl(tag) {
  const node = {
    tagName: String(tag).toUpperCase(),
    children: [],
    parentNode: null,
    style: {},
    className: '',
    id: '',
    attrs: {},
    value: '',
    checked: false,
    disabled: false,
    type: '',
    textContent: '',
    _on: {},
    appendChild(child) {
      node.children.push(child);
      child.parentNode = node;
      return child;
    },
    setAttribute(k, v) {
      node.attrs[k] = String(v);
      if (k === 'id') node.id = String(v);
      if (k === 'type') node.type = String(v);
      if (k === 'class') node.className = String(v);
    },
    getAttribute(k) {
      return Object.prototype.hasOwnProperty.call(node.attrs, k) ? node.attrs[k] : null;
    },
    addEventListener(type, fn) {
      (node._on[type] || (node._on[type] = [])).push(fn);
    },
    removeEventListener(type, fn) {
      node._on[type] = (node._on[type] || []).filter((f) => f !== fn);
    },
    focus() {},
    remove() {
      if (!node.parentNode) return;
      node.parentNode.children = node.parentNode.children.filter((c) => c !== node);
      node.parentNode = null;
    },
    click() {
      const ev = { preventDefault() {}, target: node };
      return Promise.all((node._on.click || []).map((fn) => fn(ev)));
    },
    querySelector(sel) {
      const found = allMatch(node, sel);
      return found.length ? found[0] : null;
    },
    querySelectorAll(sel) {
      return allMatch(node, sel);
    },
    classList: {
      toggle(name, on) {
        const parts = node.className.split(/\s+/).filter(Boolean);
        const has = parts.indexOf(name) !== -1;
        const next = on === undefined ? !has : !!on;
        const set = [];
        for (let i = 0; i < parts.length; i++) if (parts[i] !== name) set.push(parts[i]);
        if (next) set.push(name);
        node.className = set.join(' ');
      },
      add(name) { this.toggle(name, true); },
      remove(name) { this.toggle(name, false); }
    }
  };
  Object.defineProperty(node, 'innerHTML', {
    configurable: true,
    get() { return ''; },
    set(v) {
      if (v === '' || v == null) node.children = [];
    }
  });
  return node;
}

function loadApp(search) {
  const calls = [];
  const store = new Map();
  const document = {
    children: [],
    createElement: makeEl,
    createTextNode(text) {
      const n = makeEl('#text');
      n.textContent = text;
      return n;
    },
    createDocumentFragment() { return makeEl('#fragment'); },
    addEventListener() {},
    removeEventListener() {},
    querySelector(sel) {
      const found = allMatch(document, sel);
      return found.length ? found[0] : null;
    },
    querySelectorAll(sel) { return allMatch(document, sel); },
    getElementById(id) { return document.querySelector('#' + id); }
  };
  function mount(id) {
    const n = makeEl('div');
    n.id = id;
    document.children.push(n);
    return n;
  }
  mount('modal-root');
  mount('auth-area');
  mount('toast-root');
  mount('view');

  const location = { search: search || '', hash: '#/', href: 'https://tryoids.com/' + (search || '') };
  const sandbox = {
    document: document,
    location: location,
    localStorage: {
      getItem(k) { return store.has(k) ? store.get(k) : null; },
      setItem(k, v) { store.set(k, String(v)); },
      removeItem(k) { store.delete(k); }
    },
    fetch: async function (url, opts) {
      const body = opts && opts.body ? JSON.parse(opts.body) : null;
      calls.push({ url: String(url), method: opts && opts.method, body: body });
      return {
        ok: true,
        status: 201,
        headers: { get: () => 'application/json' },
        json: async () => ({ username: 'some_bot', api_key: 'oids_testkey', created_at: '2026-10-15T00:00:00.000Z' }),
        text: async () => ''
      };
    },
    setTimeout: function (fn, ms) {
      const t = setTimeout(fn, ms);
      if (t && typeof t.unref === 'function') t.unref();
      return t;
    },
    clearTimeout: clearTimeout,
    URLSearchParams: URLSearchParams,
    console: console,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    window: null
  };
  sandbox.window = {
    addEventListener() {},
    removeEventListener() {},
    scrollTo() {},
    location: location,
    document: document
  };
  vm.createContext(sandbox);
  vm.runInContext(SOURCE, sandbox, { filename: 'frontend/app.js' });
  return { sandbox: sandbox, calls: calls, document: document };
}

function q(doc, sel) {
  return doc.querySelector(sel);
}

function button(doc, text) {
  const buttons = allMatch(doc, 'button');
  for (let i = 0; i < buttons.length; i++) {
    if (buttons[i].textContent === text) return buttons[i];
  }
  return null;
}

async function submitSignup(app, username, password) {
  const user = q(app.document, '#auth-username');
  const terms = q(app.document, '#auth-terms');
  const age = q(app.document, '#auth-age');
  assert.ok(user, 'username field');
  assert.ok(terms, 'terms checkbox');
  assert.ok(age, 'age checkbox');
  user.value = username || 'some_bot';
  terms.checked = true;
  age.checked = true;
  if (password) q(app.document, '#auth-password').value = password;
  const submit = button(app.document, 'Create account');
  assert.ok(submit, 'create account button');
  await submit.click();
  assert.equal(app.calls.length, 1, 'signup should call fetch once');
  return app.calls[0];
}

test('valid ?code= prefills #auth-invite', () => {
  const app = loadApp('?code=inv_Ab12_cd');
  app.sandbox.openAuthModal('signup');
  const field = q(app.document, '#auth-invite');
  assert.ok(field);
  assert.equal(field.value, 'inv_Ab12_cd');
});

test('invalid or missing ?code= leaves #auth-invite empty', () => {
  const cases = [
    '',
    '?other=1',
    '?code=',
    '?code=inv_ab',
    '?code=inv_abcde',
    '?code=nope_abcdef',
    '?code=inv_bad%20code',
    '?code=inv_' + 'a'.repeat(65),
    '?code=INV_abcdef'
  ];
  for (let i = 0; i < cases.length; i++) {
    const app = loadApp(cases[i]);
    app.sandbox.openAuthModal('signup');
    const field = q(app.document, '#auth-invite');
    assert.ok(field, cases[i]);
    assert.equal(field.value, '', cases[i]);
  }
});

test('login modal has no invite field', () => {
  const app = loadApp('?code=inv_abcdef');
  app.sandbox.openAuthModal('login');
  assert.equal(q(app.document, '#auth-invite'), null);
});

test('signup POST sends username, accept_terms, age_attest, and empty invite_code', async () => {
  const app = loadApp('');
  app.sandbox.openAuthModal('signup');
  const call = await submitSignup(app);
  assert.equal(call.method, 'POST');
  assert.equal(call.url, 'https://api.tryoids.com/api/signup');
  assert.deepEqual(call.body, {
    username: 'some_bot',
    accept_terms: true,
    age_attest: true,
    invite_code: ''
  });
});

test('signup POST sends the prefilled invite code, and an edited value', async () => {
  const app = loadApp('?foo=1&code=inv_abcdef');
  app.sandbox.openAuthModal('signup');
  let call = await submitSignup(app);
  assert.deepEqual(call.body, {
    username: 'some_bot',
    accept_terms: true,
    age_attest: true,
    invite_code: 'inv_abcdef'
  });

  app.calls.length = 0;
  app.sandbox.openAuthModal('signup');
  q(app.document, '#auth-invite').value = '  inv_typed1  ';
  call = await submitSignup(app, 'some_bot', 'longpassword');
  assert.deepEqual(call.body, {
    username: 'some_bot',
    accept_terms: true,
    age_attest: true,
    invite_code: 'inv_typed1',
    password: 'longpassword'
  });
});

test('login POST stays username and password', async () => {
  const app = loadApp('?code=inv_abcdef');
  app.sandbox.openAuthModal('login');
  q(app.document, '#auth-username').value = 'some_bot';
  q(app.document, '#auth-password').value = 'longpassword';
  await button(app.document, 'Log in').click();
  assert.equal(app.calls.length, 1);
  assert.equal(app.calls[0].url, 'https://api.tryoids.com/api/login');
  assert.deepEqual(app.calls[0].body, { username: 'some_bot', password: 'longpassword' });
});
