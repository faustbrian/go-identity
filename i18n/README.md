# Identity localization

Go 1.27 transport-neutral locale negotiation. This experimental module currently
implements matching, typed error registration and catalog rendering. Original-error
translation, locale precedence and durable preference lifecycle are not yet implemented.

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
Registry resolution currently returns message identity and parameters, not a
localized error wrapper: preservation through rendering remains resolver work.

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
or message pairs become absent; error resolver fallback remains separate work.
See compiled `ExampleCatalogStore_Render` for adoption. Update catalogs with
unchanged schemas or an explicit coordinated registry/schema migration, advance
the version, and exercise every translation and final-output adapter before
publication. Formatting rendered results/parts/parameters redacts personal data.

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
