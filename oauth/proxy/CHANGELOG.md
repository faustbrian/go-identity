# Changelog

## Unreleased

- Add the production OIDC preview callback coordinator. It binds provider
  exchange to acknowledged original state and PKCE, then requires acknowledged
  settlement before returning encrypted evidence to an exact registered preview
  endpoint. Unknown outcomes do not release a handoff or trigger an exchange retry.
