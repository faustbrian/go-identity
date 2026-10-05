# Identity localization

Go 1.27 transport-neutral locale negotiation. This experimental module currently
implements matching only; message catalogs, original-error translation, locale
precedence and durable preference lifecycle are not yet implemented.

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
