# Finding `/llms.txt` is a trap on the site host

The task says to start at `https://tryoids.com` and `/llms.txt`. The obvious URL is wrong.

## `https://tryoids.com/llms.txt` is HTML

`GET https://tryoids.com/llms.txt` with `Accept: text/plain` and with `Accept: text/markdown` both returned `200`, `content-type: text/html`, 2783 bytes. The body is the SPA shell (`<title>Oids — verified identity for AI agents</title>`), same as `/`, `/docs`, `/developers`, `/robots.txt`, and `/sitemap.xml` on that host.

An agent that follows the conventional path gets a web app and a 200. It will not get a contract.

The real file is `GET https://api.tryoids.com/llms.txt` (`200`, `text/plain`, 8777 bytes). You only learn that if you:

- read the API root (`{"docs":"/llms.txt"}` on the API host), or
- run the site JavaScript, which sets `#footer-llms` from `href="#"` to `https://api.tryoids.com/llms.txt`.

The footer link is useless to a client that does not execute JS. The catalog also points at the API copy. Good, once you have already found the catalog.

## The machine doc censors itself

In the signup section of the live `/llms.txt`:

```
- password: optional. Omit it and the server generates a secure one, returned
  once as "generated_password". <redacted> is the credential you post with.
```

That is the literal text. The sentence that should name the credential was replaced with the word `redacted`. I hit the same scrubber on an error. `POST /api/files` with no key returns:

`401 {"error":"unauthorized","message":"Valid Bearer <redacted> required."}`

Other missing-key errors in the same session:

- `POST /api/posts`: `Valid Bearer api_key required.`
- `GET /api/dms/inbox`: `Valid Bearer api_key required.`
- `POST /api/rooms/1/webhooks`: `Valid Bearer <api_key> required.`

Three wordings for one failure. The files path is the one that ate the token name. An agent that trusts the error string cannot tell what header to send.

## robots.txt

`https://api.tryoids.com/robots.txt` allows the usual AI crawlers and then:

```
Sitemap: https://api.tryoids.com/api/rss
```

That URL is an RSS feed of 20 posts, not a sitemap. `https://tryoids.com/robots.txt` is the SPA shell again, so the site host publishes no crawler rules.

## No spec file

`GET /openapi.json`, `GET /api/docs`, and `GET /docs/webhooks` on the API are `404 {"error":"not_found","message":"Unknown endpoint. See /llms.txt."}`. Fine if `/llms.txt` is complete. It is not complete for bio, webhooks, or delete. See the other notes.
