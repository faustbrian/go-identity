# Optional delivered magic-link authentication

This is backend composition, not a login UI. The public reference library owns
the native transaction, capability, encrypted delivery, risk and session wiring.
Consumers supply configuration, retained keys, bounded authorization policy,
templates and the external sender; they do not implement missing domain stores.
The baseline CLI does not implicitly select magic-link authentication.

## Select native owners and HTTP independently

Set `StoreConfiguration.MagicLink` to `MagicLinkConfiguration`:

- `Request` is the native `magiclink/postgres.RequestConfig`. Supply the actual
  issuer/capability keys, original browser-cookie keys, address policy, tenant
  authority, risk policy identity, callback allowlist and bounded lifetime.
  Leave `Risk.Evaluation`, `Delivery.Owner` and `Delivery.Renderer` zero: the
  graph supplies its existing counted risk and encrypted delivery owners.
- `Consume` selects native explicit consumption and its session issuer/CSRF
  policy. Nil selects request only; it cannot issue a session.
- `PreAuth` selects the original `magic-link` browser-flow issuer, with the
  exact configured origin, callback, cookie policy and retained lookup key.
- Select `Request.Signup` and its matching possession policy only when
  `SignupIfAllowed` is permitted. Signin-only remains a separate intent. New
  prospective requests and delivery create no account; successful consumption
  owns atomic account creation. Existing eligible accounts are not recreated.

The current graph shares its OTP pre-auth/session namespace and common authority
configuration; this is not OTP authentication. All selected issuers must agree
with the existing session reader/logout profile, cookie policy and keys.
`FeatureSet.MagicLinkRequest()`, `MagicLinkConsume()` and `MagicLinkPreAuth()`
provide guarded native ports. They retain graph initialization, tenant and
shutdown checks, including retained handles and recovery.

Set `HTTPMagicLink.Request` and `HTTPMagicLink.Consume` only for the desired
routes. Supply the actual original browser-device issuer and shared HTTP rate
configuration. The graph provides the native owners, not arbitrary handlers.
Disabled selections expose no corresponding route or advertised operation.

| Selection | Route |
| --- | --- |
| Original pre-authentication | `POST /v1/session/preauth-issue`, method `magic-link` |
| Request | `POST /v1/magic-link/request` |
| Explicit consumption | `POST /v1/magic-link/consume` |
| Separately selected session reads/logout | Existing session feature |

## Apply the selected history before serving

Use the graph's public migration Check/Plan/Apply workflow before Initialize
and readiness. Request/consumption select the native capability, factor-authority
and session-purpose histories. Signup additionally selects
`identity_registration`, `identity_magiclink_registration` and
`identity_magiclink_signup_factors`, preserving the actual installed prefixes.
Do not manually copy SQL, rewrite historical checksums or infer a predecessor
from a desired login policy. Missing or incompatible live history denies serving.

## Consumer journey

1. Create the selected graph through `ComposeStores`, `ComposeProviders`,
   `ComposeWorkers`, `ComposeFeatures` and `NewServer`. Apply its migration plan,
   initialize features and confirm readiness. For signin-only, the account must
   already have an eligible verified address; the test below creates and verifies
   it through the real registration and captured-delivery owners.
2. Request an original flow using method `magic-link`; retain the issued host-only
   flow and signed browser-device cookies. Submit the actual flow ID, email,
   `signin-only` or explicitly allowed `signup-if-allowed` intent, configured
   callback and command ID to the request route with one `Idempotency-Key`.
   Preserve original inputs and that key for matching retries. The response is
   neutral metadata, never the token or permission to infer account existence.
3. Schedule `WorkerSet.ProcessDeliveryOne` through the owned worker. Only a
   committed encrypted intent reaches the bounded external sender. The selected
   template places the bearer in an HTTPS URL fragment, not query/referrer data.
   Do not log, persist as plaintext lookup data, or forward that fragment/token
   to another origin. Captured local sender output is not real provider delivery.
4. A scanner's ordinary landing GET does not consume or authenticate; this
   backend exposes no automatic GET-consumption route. Explicitly submit the
   original token, flow/cookies, command ID and exact bound callback to the POST
   consume route. A newer request supersedes the old unused link. The old link
   cannot issue a session even when its queued message arrives later.
5. Successful known commitment issues the actual session cookie and synchronizer.
   Read the session and sign out through the separately selected session owner.
   Repeating consumption cannot issue another session or redeliver credentials.
   Superseded, wrong-browser, invalid or expired custody denies without creating
   an account/session or consuming a different link.

Inspecting signatures with the native `magiclink.NewInspector` is not permission
to authenticate. It is explicitly non-consuming and cannot establish current
database authority. Native consumption owns one-use reservation/finalization
with the protected identity/session transaction. Recovery through the native
request/consume ports reconciles original metadata, not a new logical attempt,
renewed proof or replacement session credential. Never blindly resubmit after
unknown commitment.

The selected single-factor profile requires current authoritative known-empty
factor state. Enrolled/unknown state cannot fall back to a single-factor session.
`MagicLink.TOTP` and its HTTP completion are separate explicit selections; this
walkthrough does not claim their enrollment, recovery-code or trusted-device
behavior, nor complete unit/platform release qualification.

## Reproduce with disposable PostgreSQL

Use the disposable loopback PostgreSQL cluster described in
[the baseline guide](BASELINE.md). Set `IDENTITY_REFERENCE_POSTGRES_PORT` to its
exact port and use task-owned Go build/module/temporary caches. From this module:

```sh
GOWORK=off go test -race -tags=integration \
  -run '^TestReferencePostgresMagicLink.*HTTPS$' -count=1 -v .
```

The three profiles cover existing verified signin-only, new optional signup and
signup-intent login of an existing account. Accounts, original browsers, links,
queued delivery and sessions come from actual public owners. Only external HIBP
IO and the sender are controlled. Assertions cover scanner safety, supersession,
original request retry, foreign browser denial, one protected consumption/session,
no premature/duplicate account creation, replay withholding and session logout.
Additional signin/new-signup cases lose the actual final COMMIT acknowledgement
and prove credential-free original recovery, one account/session/use outcome,
and no repeated effects or credential redelivery on the original retry.
