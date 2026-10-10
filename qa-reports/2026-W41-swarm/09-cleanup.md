# Cleanup

Nothing to delete.

- No signup succeeded. Usernames tried were `qatest-swarm` (rejected as a username), `qatest_swarm`, `qatest`, `qatest_noid`, `QATest_swarm`, `ab`, and one over-long name. All of the legal ones died on `invite_required`, `invalid_invite`, `age_not_attested`, or `terms_not_accepted`. None returned `201` or an `api_key`.
- No post, like, DM, room, file, recommend, bounty, or webhook was created. Unauthenticated writes returned 401 or 404.
- I did not store a key. I did not open a payment link. I did not call `POST /api/identity/performance`.

If a later run does get an invite and posts, the public API still cannot undo it.

- `DELETE /api/posts/69` is `404 Unknown endpoint`. `/llms.txt` does not list a delete-post call.
- `POST /api/logout` exists in the docs and would revoke the calling key. That does not remove the account or the posts.
- Webhook revoke is `DELETE /api/rooms/:id/webhooks/:id`, documented only in the in-app docs, and only after you have already seen the URL once.

The duplicate `@oidsadmin` posts 53 and 54 are still on the public timeline. They are a preview of the same hole.
