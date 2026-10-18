# Identity localization

Go 1.27 transport-neutral locale negotiation. This experimental module currently
implements matching, typed error registration, catalog rendering and original-error
resolution with locale precedence, configured fallbacks and preference policy.
Durable preference persistence and lifecycle/export are not yet implemented.

```go
locale, err := (i18n.DefaultMatcher{}).Match(i18n.MatchInput{
    Requested: []string{"fi-FI", "en;q=0.8"},
    Supported: []i18n.Locale{"en", "fi"},
    Default: "en",
})
```

## API and adoption

- `CanonicalLocale` validates bounded strict BCP 47 tags against the pinned
  `golang.org/x/text/language` tables. It does not accept underscores or whitespace.
- `DefaultMatcher.Match` implements the `Matcher` interface. Inputs are immutable
  during a call; the matcher keeps no state and is safe for concurrent calls.
- `ParseAcceptLanguage` accepts a caller-extracted header, bounded to 4096 bytes
  and 32 basic ranges. It strips SP/HTAB separators, preserves ordering/weights,
  and returns no partial list on error. HTTP extraction remains transport-owned.
- `MatchInput` permits 32 requested entries (64 bytes each), 256 supported tags,
  and 256 sorted explicit aliases. Defaults and alias targets must be supported
  canonical tags; aliases must be acyclic. Configuration order is intentional.

Matching is exact progressive lookup, not linguistic similarity. Regional and
extension/private-use suffixes fall back by removing trailing subtags and their
singletons. Quality weights use integer thousandths; equal weights preserve
request order. Duplicate canonical requested ranges fail instead of guessing
conflicting weights. Explicit zero weights exclude prefix matches; a more
specific positive range can override a broader exclusion. Wildcards defer to
remaining concrete preferences; absent matches select the eligible default,
then the first eligible configured locale.
If all are excluded, `NoAcceptableLocaleError` is returned, never an excluded
locale. Unsupported preferences do not add catalog keys and must not be stored
as accepted; preference mutation must validate the supported resolved locale.

The matching algorithm is based on [RFC 4647 lookup](https://www.rfc-editor.org/rfc/rfc4647.html#section-3.4)
and [HTTP language preferences](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4).
Extended wildcard ranges and malformed list elements are rejected. Empty list
elements are ignored, with a 31-comma bound even for empty elements, following
[HTTP recipient list parsing](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2).
Tag structure and duplicate variants/singletons are checked before upstream
canonicalization; repeated private-use subtags remain valid. Full pinned official-fixture/interoperability,
coverage, mutation and release evidence remain pending.

## Security and privacy

Language input is personal data, not authentication or a demographic signal.
No preferences, cookies, headers, audit records or telemetry are persisted here.
Errors and `MatchInput` formatting redact raw inputs. A canonical tag or a
match does not prove consent, tenant ownership or preference-write authority.
Consumers must not log raw preference/header input or use it as an unbounded
telemetry label. HTTP consent/cookie integrity and durable preference deletion
will retain their separate owners; matching alone cannot acknowledge either.

No rendered strings or escaping are provided by this matcher. Final delivery
and HTTP context owners must perform context-specific escaping exactly once.

## Typed error registration

Construct `NewErrorRegistry()`, register each domain-owned `ErrorIdentity` once
using `Register(identity, messageID, ParameterSchema)`, then call
`SealErrorRegistry(registry)` before `Resolve(error)`. Zero/nil registries and
unsealed resolution fail closed. Sealing is idempotent, shared across copies,
and irreversible; registration after sealing or duplicate ownership is an error.
At most 10000 identities can be registered. Registration is synchronized, but
the caller must not mutate a schema during its call; schemas are copied.

`LocalizableError` exposes only `ErrorIdentity()` and `SafeParameters()`. Registry
lookup never calls `Error()` or custom `As()` and never guesses identity from
text. Wrapped/joined errors are visited depth-first, left-to-right, bounded to
32 nodes. The first typed owner controls resolution; unknown/invalid typed
wrappers cannot bypass into an inner translation. Cycles, excessive wrapper
fan-out and callback panics fail closed without leaking diagnostics. Callback
implementations must themselves obey a bounded-work contract; the registry
does not start goroutines or claim it can cancel arbitrary caller code.

Schemas declare at most 32 uniquely named string/bool/int64/time scalars and
their final plain-text, URL, header, JSON or HTML contexts. Strings are UTF-8 and
at most 4096 bytes; only the selected scalar arm may be populated. List/float/
arbitrary-object values are rejected. Missing, extra, duplicate, wrong-kind or
wrong-context values return zero/false, never a partial translation. Returned
values are copied in schema order, not escaped or rendered. Empty string,
false and integer zero remain present values; time must be nonzero.

The owning package must register only public-safe values. Schema validation
does not detect secrets hidden in an otherwise valid string. `SafeParameter`
formatting is redacted even for public-safe personal data. Unknown errors
remain untranslated; the original typed error is neither altered nor replaced.
Registry resolution returns message identity and parameters, not a localized
error wrapper. The resolver below adds rendering and preserves the causal chain.

See the compiled `ExampleErrorRegistry_Resolve` for an external-package example.

## Catalog authoring and publication

`NewCatalogStore([]Catalog)` validates and freezes a snapshot of 1..256 canonical
locales, all with one positive version. Each locale has 1..10000 unique messages;
the whole snapshot permits at most 10000 messages and 8 MiB template source.
Templates are UTF-8, 1..8192 bytes and at most 256 compiled parts. Message IDs
have `MessageID` syntax; schemas have `ParameterSchema` bounds. Placeholder
sets, kinds and contexts for the same ID must agree across translations;
declaration order may differ. Every declared placeholder must be used.

The restricted Go-template action grammar is:

```text
{{value "name" "plain-text"}}
{{plural "count" "=0" "none" "one" "attempt" "other" "attempts"}}
{{select "mode" "fast" "Fast" "other" "Standard"}}
```

All arguments must be constant quoted strings. `value` requires an exact
declared name and context (`plain-text`, `url`, `header`, `json` or `html`).
`plural` requires int64, with exact canonical `=integer` choices and/or CLDR
`zero`, `one`, `two`, `few`, `many`, `other` categories. Exact choices precede
categories; cardinal categories use pinned upstream x/text rules, including
full-width signed integers without float conversion. `select` requires string
or bool (bool keys are `true`/`false`). Choices are literal text, not recursively
parsed templates. Each choice operation permits at most 16 unique keys and must
include `other`. This is a documented restricted language, not ICU MessageFormat
or unrestricted Go-template execution. Pipelines, dot/method/variable access,
control-flow nodes, template calls and associated/root-redefined templates are
unsupported; no template is executed. The standard-library parser produces
an AST that is compiled only into closed scalar operations.

`Render(ctx, locale, messageID, []Parameter)` performs exact lookup without
fallback and returns one snapshot's `RenderedMessage`. Missing pairs and invalid
parameters are classified errors; cancellation and empty/oversized output return
no partial result. Output is bounded to 8192 bytes. Strings remain unescaped,
integers use decimal, booleans use `true`/`false`, and times use UTC RFC3339Nano.
`Parts` retain literal/value boundaries and each value's declared context;
`Parameters` retain exact typed values. The `Message` string is an unescaped
preview, **not** safe HTML, a header, URL or serialized JSON. Final-output owners
must validate actual placement and escape per context exactly once; declaration
matching here does not infer final transport syntax or authorize unsafe placement.

`Replace(expectedVersion, completeCatalogs)` compiles before atomically publishing
a strictly greater version. Concurrent publishers at one expected version have
at most one winner. Failed compilation/CAS leaves the previous snapshot intact;
no automatic retry or merging occurs. `Locales()` returns a copied list and
version. Do not copy stores or mutate construction/render inputs during calls.
Readers see one complete old/new snapshot, never a mixed version. Removed locale
or message pairs become absent unless resolver admission constrains their removal.
See compiled `ExampleCatalogStore_Render` for adoption. Update catalogs with
unchanged schemas or an explicit coordinated registry/schema migration, advance
the version, and exercise every translation and final-output adapter before
publication. Formatting rendered results/parts/parameters redacts personal data.

## Typed error resolution

`NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs})` admits
registered message/schema pairs and seals the registry on success. Every
registered message needs at least one translation; every present translation
must match its typed schema. A failed constructor leaves an unsealed registry
open. Admitted catalog updates must retain those schemas and at least one
translation per message; configured alias targets cannot be removed. This
shares the existing catalog publication lock, not a second update mechanism.

`Resolve(ctx, ResolveInput{Explicit: "fi-FI", Default: "en", Error: original})`
selects explicit preference, authenticated stored session preference, trusted
cookie, header, then default. Unsupported preferences fall through. Regional
preferences progressively match available translations; a higher supported
preference overrides lower header exclusions. All input syntax is validated,
even lower-priority sources. The default must be canonical and have this message;
absence fails rather than translating an unrelated message or guessing English.
Translation availability is evaluated from the same immutable snapshot used
to render, even if a callback publishes a replacement during selection.

Transport owners authenticate stored/cookie preferences and extract the header.
This API does not infer trust, persist fallback locales, inspect error strings,
call custom `As`, or replace the originating typed error. `LocalizedError`
retains `Cause`, stable `Code`, `MessageID`, original typed parameter values,
selected `Locale`, preview `Message`, typed `Parts`, and `CatalogVersion`.
`errors.Is`/`errors.As` follow its original causal chain. Diagnostic `Error()`
and formatting are constant/redacted; use the explicit `Message` field for
public rendering and final-owner escaping. Failures return no partial localized
result and a `ResolutionError` unwrapping both the classified reason and original
error, including cancellation. Unknown/malformed owners are never guessed.

An optional `Matcher` receives copied bounded inputs. It must be bounded,
concurrent-safe and honor `MatchInput` negotiation semantics, including zero
weights. Exact configured aliases resolve before upstream full-tag
canonicalization; progressive parents are then derived from that canonical
identity, never from raw grandfathered spellings or parent-only aliases.
Matcher inputs have aliases already resolved. Preference calls contain
positive progressive parents plus `*;q=0`
to suppress automatic fallback; `NoAcceptableLocaleError` advances to the next
source. Header/default calls preserve original weights on normalized ranges. The resolver
rejects unavailable output keys and redacts callback errors/panics; cancellation
is checked before/after calls. It cannot interrupt arbitrary caller code and
does not create a goroutine to conceal that limitation.

### Adapting an existing identity operation

The compiled `ExampleDefaultResolver_Resolve_identityValidation` in
[identity_consumer_test.go](identity_consumer_test.go) consumes the public
`identity.User.Validate` operation and its real `identity.InvalidInputError`.
An application-owned adapter registers `example.user.invalid` and the separate
`user.invalid` message ID for the exact known `user_id` failure. It keeps the
original error in `Unwrap`, so localization retains `errors.Is`/`errors.As` and
the original typed field; it never classifies by diagnostic text. The example's
machine identity is the application's explicit mapping, not a new kernel code.
Unadapted errors, matching diagnostic strings and unrecognized field values do
not acquire a translation or become public interpolation data.

The example passes competing locale-source inputs, selects Finnish through
regional lookup, and renders a deliberately bracketed safe
field label through `html/template` only at the final HTML text boundary. The
original typed parameter stays `<user ID>`; the final output contains
`&lt;user ID&gt;`, not double-escaped entities. This proves an external-package,
transport-neutral consumer path, not HTTP cookie authentication, durable
preference storage, lifecycle export/deletion or reference-server integration.
Transport/session owners must establish source trust before passing these inputs.

`NewCatalog(locale, messages)` validates/canonicalizes a locale and copies
bounded messages/schemas into an explicit initial version-1 catalog.
`NewResolver(catalogs, fallbacks, registry, preferences)` implements the specified
constructor and returns `Resolver`, also implementing `PreferenceResolver` for
explicit validated `GetPreference`/`SetPreference` and `LocalizationService`.
Construction performs no IO. The injected durable store is required, including
typed-nil rejection; there is no ignored or fabricated store argument.

Configured fallbacks are 1..16 unique canonical supported tags. Every registered
message needs at least one configured fallback translation. A call's `Default`
must belong to that chain; if its translation is absent, the first available
configured fallback is selected. Header exclusions remain effective, and chain
order controls excluded-default fallback before other supported translations.
`ResolverConfig.Fallbacks` adds the same behavior to shared-store composition;
when omitted, its original per-call default behavior remains unchanged. Admission
pins all fallback locales and each registered message's first initially available
fallback pair; publishing cannot silently remove those pairs. Change those
constraints by constructing a new coordinated composition. Templates may still
be replaced atomically under the existing immutable-schema constraints.

## Preference policy and privacy

`PreferenceKey` binds exact tenant and personal-data subject. Commands bind
canonical accepted locale, expected version (zero=create), positive accepted
notice version and a canonical stable `identity.CommandID`. `NewPreferencePolicy`
copies a fixed 1..256 supported-locale policy and requires a callback timeout
greater than zero and no more than 30 seconds. Canonical `NewResolver` composition
uses its catalog locales and a documented five-second timeout. Policy updates
and catalog migrations must explicitly reconcile stored preferences; reads and
resolution never store a negotiated fallback or raw header/cookie contents.

The policy validates structural inputs and exact returned tenant/subject/locale/
version/notice projections. It does **not** grant authorization, prove consent,
normalize canonical IDs, or substitute for lifecycle fencing. Its caller must
already hold authenticated authorized scope. The durable operation owner must
enforce canonical-ID and accepted-notice authority, optimistic/idempotent
transactions, deleted-subject tombstones and privacy generations. The reference
server must bind those real authorities before exposing preference methods.

`PreferenceStore` exposes exactly two methods. Reads return explicit
`PreferenceNotFoundError` for absence, never inferred defaults. Writes must
atomically persist command identity and its result; identical replays return
the original result and changed same-command input conflicts. The policy invokes
at most one bounded store operation. Panic, unclassified failure or invalid
write projection returns `PreferenceOutcomeUnknownError` with the original
command ID: reconcile that command, never mint a replacement ID or infer rollback
from cancellation. Explicit no-write conflict/denial remains classified. An exact
committed result is retained even when cancellation arrives late. Callback
diagnostics are not exposed. All preference projections format redacted.

Locale is personal data. The notice version must describe purpose and retention;
the durable adapter and reference profile own retention/deletion enforcement.
Session/HTTP caches and integrity-protected cookies are projections, not durable
authority. They expire/invalidate under their respective lifecycle consumers.
Exact-snapshot export, anonymization/deletion acknowledgements, unknown-outcome
reconciliation and a concrete downstream preference adapter remain pending.

## FAQ and updates

Why no default English? Composition must explicitly choose a supported default.
The reference profile uses `en` and `fi`, with `en` default; this library does not
silently impose reference-server configuration on every consumer.

Why reject duplicate ranges? Their conflicting weights have ambiguous precedence;
the strict profile rejects ambiguity without changing machine error semantics.

How are alias tables updated? Upgrade the pinned upstream dependency with
canonicalization regressions and adoption review. Custom aliases are explicit
immutable input; they do not change upstream data or persisted accepted tags.
See [CHANGELOG.md](CHANGELOG.md) for release notes.
