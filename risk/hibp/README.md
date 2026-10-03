# HIBP password screening

Experimental, Go 1.27. This module is **not yet a usable password checker**.
There is no public prefix-input API or password acceptance decision.

## Implemented privacy boundary

The owned parser validates an entire bounded response before making any match
available. It accepts exactly 35 ASCII hexadecimal suffix characters, one colon
and 1..10 unsigned ASCII decimal digits. Hexadecimal case is canonicalized;
leading decimal zeros are accepted within that width. LF and CRLF are supported,
with an optional final newline. Empty responses, interior blank lines, embedded
carriage returns, malformed tails, partial reads and conflicting duplicate
counts—including zero/positive conflicts—fail closed. Identical duplicates
collapse. Zero counts are padding, never a breach.

The response limit is explicitly 1 KiB..2 MiB; the count maximum is 1..1 billion.
Rows have at most 46 bytes excluding CRLF. Row count is bounded by the byte limit
and minimum row size; the parser uses a fixed 64-byte streaming buffer and never
copies a complete response. Suffix matching visits every parsed entry using
constant-time comparison, with no early acceptance at a matching row. Response
size still affects processing time; this does not claim network timing privacy.

Candidate derivation borrows `go-password.Secret` synchronously, preserves every
byte without trimming or normalization, and never destroys the caller's owner.
The selected candidate limit is positive and at most 1 MiB. Only five uppercase
hexadecimal characters can become a future request prefix; the remaining suffix
stays private. SHA-1 is used solely for the protocol, never password storage.
Transient hash/encoding buffers are cleared, and private values reject automatic
serialization and redact formatting. Go cannot guarantee runtime-wide erasure.

The protocol basis is the official [Pwned Passwords range and padding
documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords), consulted
2026-10-03. Synthetic local tests are not provider interoperability evidence.

## Remaining implementation

`Checker.Check`, scoped request/results, fixed HTTPS endpoint, redirect refusal,
padding headers, bounded transport, cache expiry/LRU, same-prefix coalescing,
outbound concurrency, caller cancellation, shutdown, normalized risk evidence,
audit/telemetry and password workflow composition remain unfinished. No provider
request is performed by this checkpoint. Do not substitute parsing success for
clean-password evidence or risk allowance.

The password dependency pins committed Secret ownership at `c5746af64a6f`.
Local development uses disposable external workspace wiring; no permanent
replace directive is included. Publication, clean-consumer/API, exact coverage,
mutation, interoperability and other release gates remain pending.
