# GitLab selected protocol sources

Reviewed on 2026-11-14:

The official GitLab source snapshot is commit
`b95c5eab90c9127e501d7155b27aa9049e0da7bc`, resolved from GitLab's public repository
API on that date. The docs are CC BY-SA 4.0; no complete document is vendored.
Immutable source references are
[OAuth2](https://gitlab.com/gitlab-org/gitlab/-/blob/b95c5eab90c9127e501d7155b27aa9049e0da7bc/doc/api/oauth2.md)
and [users](https://gitlab.com/gitlab-org/gitlab/-/blob/b95c5eab90c9127e501d7155b27aa9049e0da7bc/doc/api/users.md).
Raw-document SHA-256 pins are
`89b961feb05a0e4ed3c475ab9d35303b12f65174e78b72cf4bc34fa01f5485a9`
for OAuth2 and
`cfa36eee98814c67619ae99b05b00d36d8d663e882e8151ebc12585c7ee1c29d`
for users. An update resolves a new immutable official revision, reviews the
selected facts and records new exact raw-document digests before testing it.

- [GitLab OAuth2 provider API](https://docs.gitlab.com/api/oauth2/): authorization
  code/S256, state, form client credentials and bearer REST access. This selected
  catalog profile requests only `read_user`; it does not select `/oauth/userinfo`.
- [GitLab Users API](https://docs.gitlab.com/api/users/#get-the-current-user):
  bearer current-user response and integer `id`. Email/username are not stable
  identity evidence in this profile.
- [RFC 9700 section 4.4.2.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2.2):
  distinct redirect URIs as a mix-up defense, including validation of the actual
  route against the authorization server originally selected by the client.

## Independent test implementation

The task-owned native consumer uses the independent
[`github.com/go-oauth2/oauth2/v4` v4.6.0](https://github.com/go-oauth2/oauth2/tree/e444dfa1af98b5e2d4d9ff5dbb0747ad9e82c218),
MIT licensed. Normal module proxy/checksum-database authentication returned:

```text
origin e444dfa1af98b5e2d4d9ff5dbb0747ad9e82c218
module h1:g1M92LQh9NbDmovPNG2iJ25rtbXPXBrRv+lorehLc44=
go.mod h1:BXiOY+QZtZy2ewbsGk2B5P8TWmtz/Rf7ES5ZttQFxfQ=
```

Its server/manager performs actual code generation, S256 validation, POST
credential verification, one-use exchange and bearer-token validation over
verified loopback TLS. A separate test resource maps that independently
validated bearer identity to the documented GitLab REST integer-ID shape.
This proves independent OAuth2 protocol composition with the GitLab response
contract, not a live GitLab server, GitLab authorization UI or deployment.
It is test-only and not a Golib runtime dependency. Updating the oracle requires
reviewing its source/license and authenticating a new exact module checksum;
mutable branches or local replacements are not pins.
