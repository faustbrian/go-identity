# Changelog

## Unreleased

- Add explicit required, optional-protocol and forbidden header binding into
  existing opaque idempotency-key and bearer credential contracts. Reject
  ambiguous headers and alternative key channels without reading the body or
  performing authentication; trusted routing/proxy integration remains pending.

- Add bounded ordinary JSON/form/query decoding with strict duplicate and
  Unicode rejection, separate raw/decoded budgets, framing/media checks and
  atomic typed results. Query/body inputs are never implicitly merged, and
  body ownership remains with the server or direct caller. Complete transport
  integration remains in development.

- Add explicit typed feature selection with dependency and collision rejection,
  detached metadata snapshots and canonical policy/schema bindings. Empty
  selection exposes no operations; probe selection supplies the real handlers.
  Secure routing, rate enforcement and OpenAPI rendering remain in development.

- Add separate exact-path GET liveness/readiness handlers with fixed no-store
  responses, explicit bounded composition checks and startup/drain denial.
  Provider diagnostics and readiness labels are never exposed in probe bodies.

- Add an explicit Go 1.27 HTTP server owner with validated timeouts/header
  bounds, one-shot start, deployment-supplied listeners, cooperative handler
  deadlines, graceful drain and bounded forced connection closure. Feature
  routing and complete identity transport remain in development.
