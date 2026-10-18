# Changelog

## Unreleased

- Add the fixed Siteverify v0/free provider with bounded private form requests,
  strict complete JSON, exact configured hostname/action/cdata checks, conserved
  challenge validity and typed native/transport failures. Omit remote IP and
  automatic retries; preserve transport idempotency within one trusted scope.
  Secret custody and shutdown are explicit. Live provider and full release
  qualification are not established by the synthetic protocol/TLS fixtures.
