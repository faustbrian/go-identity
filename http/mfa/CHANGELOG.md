# Changelog

## Unreleased

- Add opt-in native magic-link/TOTP completion transport and closed OpenAPI
  contract. Bind original browser/device and authenticated subject/challenge
  quotas; deliver session/CSRF credentials only on fresh matching commitment.
  Replay, error, expiry and changed final status withhold credentials.
  Reference HTTP integration and full MFA transport remain in development.
