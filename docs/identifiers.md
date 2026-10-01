# ID contracts

## API and ownership

`SubjectID` and `PreAuthTransactionID` are distinct comparable string types with
invalid empty zero values. Their constructors (`NewSubjectID` and
`NewPreAuthTransactionID`) read exactly 16 cryptographic-random bytes and reject
all-zero entropy. A failure returns no ID and the corresponding stable entropy
sentinel, without retaining bytes or exposing the provider diagnostic.

`ParseSubjectID` and `ParsePreAuthTransactionID` are bounded reconstruction
boundaries: exactly 22 unpadded base64url characters, exactly 16 decoded bytes,
and at least one non-zero bit. Padding, whitespace, invalid alphabet and alternate
unused-bit encodings are rejected, not normalized. Errors never contain inputs.
`FormatSubjectID` and `FormatPreAuthTransactionID` return an empty string for
invalid values, including invalid explicit string conversions.

`CompareSubjectID` and `ComparePreAuthTransactionID` order decoded bytes and
return -1, 0 or 1. Encoded ASCII order is different and must not replace this
comparison in cursor/storage contracts. Either invalid operand returns the
type-specific invalid-ID sentinel. Values are immutable and concurrency-safe;
these functions start no goroutines and retain no resources.

## Adoption and security

Parse stored/wire values before use; do not treat a Go conversion as validation.
Keep subject IDs distinct from pre-authentication attempt IDs. Neither parsing,
generation nor possession authorizes access, authenticates a person, reserves
a capability or opens a transaction. Bind attempts to the exact tenant,
operation and continuation at the consuming workflow boundary.

These fixed codec contracts do not define the injected owner-ID/import policy
for the shared-issuer directory. Existing canonical identifiers such as ULIDs
must be preserved by that separate policy and mapping boundary; do not force
imported owners through the subject codec or replace their IDs.

## Operations and tradeoffs

Generation uses the process cryptographic-random source, not a counter, wall
clock or pseudorandom fallback. Entropy failure denies generation. There is no
timeout or cancellation parameter in these exact constructor contracts; entropy
availability remains an operating-system concern. The generated representation
is stable but carries no timestamp, tenant or authority information.

## FAQ

- **Can I use a zero ID?** No. Parsing/comparison reject it; formatting returns
  an empty string.
- **Can I compare encoded strings?** Not for decoded numeric/byte order. Use
  the corresponding Compare function.
- **Are IDs bearer secrets?** No. Authorization and replay consumption belong
  to explicit workflow contracts, not these values.
- **Does this implement directory import or login?** Not yet; those remain
  required implementation work in the identity platform.
