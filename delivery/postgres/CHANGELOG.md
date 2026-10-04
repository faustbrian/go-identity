# Changelog

## Unreleased

- Freeze encrypted message custody under the original command and complete
  effect scope. Confidential logical identity survives randomized encryption;
  local attestation validation requires no key-provider call under transaction
  locks. Preparation and decryption cannot extend the original expiry.
  The production PostgreSQL Queue and processing lifecycle remain unfinished.
