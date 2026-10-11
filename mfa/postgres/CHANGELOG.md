# Changelog

## Unreleased

- Select the current known-empty factor generation during native reset-request
  preparation and bind it into original issuance. Missing or enrolled authority
  denies email-only recovery without initializing or inferring factor state.

- Fence original reset-completion factor generations during preparation as well
  as final mutation. Unknown, enrolled and stale generations deny before
  password work; final execution independently reacquires the primary fence.

- Add durable factor generations initialized only by genuine native signup, and
  transaction-locked known-empty admission for email password recovery. Existing
  accounts remain unknown rather than being silently treated as factor-free.
