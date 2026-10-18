# Fixed script classification

`../unicode151.go` is the 39-range, 1,442-letter intersection of
Unicode 15.1.0 `Script=Latin` and `General_Category=L*`. It is not a
normalization engine. The published `go-identifier/v2` prerequisite owns
fixed Unicode 15.1 NFC and full case folding. No compiler Unicode tables
participate in syntax decisions.

Official inputs fetched 2026-10-18, with SHA-256:

| Source | SHA-256 |
| --- | --- |
| [Scripts.txt](https://www.unicode.org/Public/15.1.0/ucd/Scripts.txt) | `0eacb65169ae6eb1d399cd70826b3da15fff19f6f586eecf819b70c83b1d9b32` |
| [UnicodeData.txt](https://www.unicode.org/Public/15.1.0/ucd/UnicodeData.txt) | `2fc713e6a31a87c4850a37fe2caffa4218180fadb5de86b43a143ddb4581fb86` |
| [DerivedCoreProperties.txt](https://www.unicode.org/Public/15.1.0/ucd/DerivedCoreProperties.txt) | `f55d0db69123431a7317868725b1fcbf1eab6b265d756d1bd7f0f6d9f9ee108b` |

The generator also proves that U+0300..U+036F are inherited nonspacing marks.
The syntax policy permits these only following a Latin base, excluding U+034F
(default-ignorable combining grapheme joiner). Normalized output must pass the
same policy, so folding an inherited mark into a Greek letter is denied.
ASCII digits and `_`, `.`, `-` are the only permitted Common characters.
These are policy restrictions, not claims that every Common character is safe.

The data is distributed under [UNICODE LICENSE V3](LICENSE.txt), fetched from
[Unicode](https://www.unicode.org/license.txt), SHA-256
`e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96`.
Only this bounded derived subset and the license are retained here; full UCD
inputs can be downloaded into a disposable directory for regeneration:

```sh
ruby scripts/latin_ranges.rb /path/to/unicode-15.1.0-ucd
```

The generator verifies all source checksums before emitting the complete Go
file to stdout. Compare its output with `unicode151.go`; updates require a new
profile identity/version, collision preflight, official-source review, and
the normalization, hostile-boundary, and composed identity consumer tests.
