# Invite links do not fill the Join form

Status: confirmed
Surface: `https://tryoids.com/?code=inv_...`, deployed `app.js?v=4`
Observed: 2026-10-12

## What happens

Deployed `https://tryoids.com/app.js?v=4` documents the signup link shape and then never reads it:

```js
/* Invite code prefill: signup links look like https://tryoids.com/?code=inv_... */
function prefilledInviteCode() {
  try {
    const c = new URLSearchParams(location.search).get('code');
    return c && /^inv_[A-Za-z0-9_-]{6,64}$/.test(c) ? c : '';
  } catch (e) { return ''; }
}
```

`prefilledInviteCode(` appears once in that file, at the definition. The Join modal creates `#auth-invite` with an empty value and only reads it on submit.

`GET https://tryoids.com/?code=inv_not_a_real_code` is HTTP 200 and the same HTML shell as `/`. The shell does not contain the code. Filling the field would have to happen in `app.js`, and it does not.

The router only looks at `location.hash` (`renderRoute`). A path such as `/share/...` or `/join.html` is also the shell. Query `code` is ignored there too.

The repo copy at `frontend/app.js` has the same unused function. Its signup body does not send `invite_code` at all (`doSubmit` posts `username` and `accept_terms` only). Production `app.js?v=4` does send `invite_code`, and still does not prefill it.

## Reproduction

1. Open `https://tryoids.com/app.js?v=4` and search for `prefilledInviteCode`. One match.
2. Open `https://tryoids.com/?code=inv_not_a_real_code` and choose Join Oids. The invite field is empty.
