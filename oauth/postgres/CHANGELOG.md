# Changelog

## Unreleased

- Compose explicitly configured OAuth2/UserInfo providers through existing
  native link and existing-account signin owners. Bind full UserInfo facts and
  the distinct actual callback route to original encrypted state/configuration;
  retain original evidence deadlines without introducing a second replay owner.

- Bind explicit Google Accounts signed-issuer policy to the existing immutable
  configuration and retained callback profile. Canonical and legacy signed
  Google issuers resolve to the same canonical issuer/exact-subject account;
  changing policy cannot reinterpret pending callbacks or replay them under a
  different selection. Strict zero-selection profile bytes and RP AAD remain
  compatible. No signup, account merge or generic issuer aliases are added.

- Adopt the explicit `client_secret_post` provider profile for native linking
  and existing-account signin. The selected token credential channel remains
  bound to original state/configuration; no migration or automatic fallback
  between public, Basic and POST profiles is introduced.

- Resolve shared link/signin callback routing from the native keyed state
  commitment, including retained terminal metadata within its original lifetime.
  Routing grants no browser or exchange authority; the selected native callback
  still authenticates its original profile and browser without method fallback.

- Add native query/S256 OIDC completion for an existing linked account and
  known-empty MFA. Bind issuance to the original callback-purpose browser and
  exact Remember policy; consume state/browser and write the session, audit,
  lifecycle and exchange-secret erasure atomically. Only the original newly
  committed invocation delivers bearer/CSRF custody; committed retry is
  tokenless and an unknown exchange is never retried. Issuer-bound provider
  denial erases custody without exchange or session issuance.

- Add tokenless signin-command recovery through the existing coordinator and
  current query policy, bound to the original anonymous flow/service actor.
  Recovery returns receipt metadata only, never a session, bearer or CSRF token;
  uncertain exchange remains pending without re-exchange. Provider-denial
  commands retain their separate profile.

- Document explicit risk `OAuthProviderDiscovery` selection, mandatory trusted
  network/device attribution, the forward-only installed session-purpose
  expansion, and existing native primary-read/same-user cookie-logout owners.
  Signup, MFA completion, email matching, automatic reference/HTTP selection,
  refresh, unlinking and complete OAuth qualification remain outside this unit.

- Add native original-preauth OAuth initiation and state/browser-authenticated
  callback-rate attribution. Original state, nonce, PKCE and expiry survive
  restart retries; tenant suspension or changed directory epochs withhold
  redirect delivery. Attribution neither consumes state nor exchanges a code.
  Provider callback/session completion and HTTP/reference signin remain open.

- Retain definitive token-endpoint refusal for atomic terminal cleanup and
  replay without another exchange or final link grant. Failed denial erasure
  preserves pending custody; trusted expired-RP maintenance can settle known
  failures without browser credentials or renewed proof authority.

- Recover expired, abandoned attached callbacks through tenant-scoped bounded
  maintenance and the existing canonical coordinator. Historical metadata can
  authorize exact erasure/release, never restore a live proof or retry exchange.

- Add bounded, cursor-paged erasure of abandoned expired link-state secrets.
  Claimed or uncertain callbacks retain their custody; callers own maintenance
  scheduling and keep the original provider/key configuration until it drains.

- Record callback handling, OAuth linking and the authoritative account mutation
  atomically with shared correlation and explicit causation. Terminal refusal
  records no mutation; exact replay does not duplicate those records.

- Keep delayed callbacks bound to their initiating session's credential epoch,
  never a newer epoch observed after exchange. Known refused links erase their
  exchange secrets atomically with terminal refusal. Failed erasure retains
  uncertain custody rather than reporting completed cleanup. RP initiation and
  callback audits use the catalog actions and standard self-service retention.

- Complete issuer-bound provider-error callbacks through the existing root
  transaction: authenticate original state/browser, consume the original grant,
  erase PKCE/proof ciphertext, record denial and replay the original error
  redirect without exchange, identity changes or session issuance.

- Use the neutral link command/participant contract and prepared one-use unit
  of work for final identity linking; the actual invocation-local writer owns
  the authoritative transition inside the existing coordinator.

- Snapshot retained coordinator and replay-key maps and policy configuration at
  construction. Later caller container changes cannot rewrite selected linking
  policy or diverge per-call coordinators from the original request-key owner.
  Borrowed policy services, provider clients and clocks remain caller-owned.

- Retain verified exchange output before the identity owner's locked collision
  decision. A known refused link now returns a terminal denial instead of an
  unknown exchange, and exact retries do not exchange again. Existing account,
  password access and session authority remain unchanged on refusal.

- Preserve original initiation and callback counter aliases across retained-key
  additions using the risk owner's optional immutable charge history. Install
  its `CounterKeyVersionMigrationSource` before selecting `NewLinkService`.
  Exact retries retain the original protected network, command and expiry;
  a new request-admission timestamp does not change original intent. Missing
  historical aliases or retired original keys deny without a new allowance or
  provider exchange.

- Add native explicit-self callback execution through the existing account-link
  journal: reserve original state before exchange, retain authenticated final
  issuance and encrypted provider tokens, fence current source authority, and
  insert tokens and erase exchange secrets in the account transaction. Original
  rate attribution survives terminal erasure without renewing its lifetime.
  Full consumer/transport acceptance and publication remain pending.

- Compose native explicit-self password-session initiation with original-key
  custody, protected counters, current factor fences and actual callback-grant
  issuance. Preserve encrypted RP bindings and nonsecret grant metadata across
  exchange-secret erasure. Callback lookup authenticates original browser,
  state, configuration and proof without releasing PKCE; complete callback/link
  and transport composition remain unfinished.

- Add forward RP transaction storage with explicit original user/pre-auth
  namespaces, bounded encrypted custody and erasure that retains lookup metadata.
  Native callback workflow and transport composition remain in development.
