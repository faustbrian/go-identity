# GitHub existing-account OAuth-app profile

```go
provider, err := providers.NewGitHub(providers.GitHubConfig{
    Version: 1,
    ClientID: clientID,
    ClientSecret: loadedSecret,
    RedirectURI: "https://application.example/github/callback",
})
if err != nil {
    return err
}
// Clear loadedSecret; the provider retains its own copy.
defer provider.Close()
```

## Selected API and native composition

`NewGitHub` returns the existing `*oauth.OAuth2UserInfoProvider`, not an SDK or
application workflow. Its closed selection fixes `github.com` authorization and
token endpoints, `api.github.com/user`, POST client authentication, code/query/S256
and exactly `read:user`, `user:email`. The stable subject is canonical decimal
positive int64 REST `id`; `login` and `email` never select a local account.

Supply this provider to native `oauth/postgres.NewLinkService`,
`NewSigninService` and `NewSigninCompletionService`. Linking requires the real
existing user's password-session/CSRF and current authority. Signin requires an
explicitly linked existing account and original native pre-auth browser. The
native owners retain single-use state, PKCE, account/current-authority checks,
rollback, replay and session issuance; consumers supply configuration, not stores.

Register a distinct callback URI for this authorization server. At its trusted
actual route, use `oauth.ParseOAuth2QueryCallbackWithPolicy(ctx, rawQuery,
receivedRoute, provider.OAuth2Profile(), provider.OAuth2TokenPolicy())`.
`receivedRoute` excludes the query and must not come from untrusted callback
parameters or forwarded Host. The registry rejects another configured provider
sharing the URI. This is RFC 9700's distinct-redirect mix-up defense, not an issuer
claim. Existing OIDC parsers still require `iss`; the GitHub variant rejects it.

## Token lifetime and rollout

Ordinary GitHub OAuth-app responses omit `expires_in`. `TokenSet.ExpiresAt()`
then returns zero; the native vault stores two SQL NULL expiry components. No
TTL, ID-token timestamps, provider nonce or authentication age is fabricated.
If a response supplies a valid positive expiry, its original exact expiry is
retained. Comma-delimited reported scopes cannot expand requested permissions.
Original UserInfo evidence is valid for at most twenty seconds from the start
of its authoritative read, capped by a supplied token expiry. Token lifetime
never extends identity evidence or native session authority.

Before enabling this profile, append and apply both phases from native
`TokenVaultOptionalExpiryMigrationSource{Schema: schema, Version: nextVersion}`
with the existing migrations runner and namespace. Reserve `nextVersion` and
`nextVersion+1` after the installed token-vault history. The first phase expands
the two expiry columns and installs a paired-NULL check without scanning; the
second validates it. Both bound lock acquisition to five seconds. Failed apply
does not permit enabling the profile. Installed migration bytes, populated
positive rows and ciphertext/AAD remain unchanged; there is no backfill/down.
Roll out readers/writers that understand this selected policy before enabling
GitHub. Old positive-expiry profiles remain strict on either schema. Disable new
GitHub admissions before rolling back to a reader that cannot handle this policy;
do not coerce existing absent expiry into a timestamp.

## Ownership, limits and unsupported operations

Construction does no IO. Secret copies/transport clone are provider-owned;
caller clocks and verified standard HTTP transport are borrowed concurrent-safe
collaborators. Close after admitted operations finish. Calls accept bounded
contexts, do not retry codes/UserInfo, prohibit redirects and retain resource
limits and redacted errors. Ambiguous post-send failures remain `Unknown`.

This finite profile does not fetch `/user/emails`, map verified email, perform
signup/implicit linking, direct native-token signin, refresh, revocation,
enterprise routing, HTTP/Reference routing or remote logout. `user:email` is the
catalog's fixed requested scope, not an email-verification implementation claim.
Local logout uses the existing native session owner and does not revoke GitHub
tokens. Tests with an independent OAuth2 server and official response fixtures
are not live GitHub interoperability or whole-provider-catalog qualification.
See [source pins and oracle boundaries](github-sources.md).
