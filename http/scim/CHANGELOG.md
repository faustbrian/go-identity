# Changelog

## Unreleased

- Add independently selected managed connection Get/List over strict-session
  bearer HTTPS, with canonical shared safe-read admission and native current
  administrator authorization. Return only bounded safe scoped projections.
- Select SCIM Bulk and matching discovery over one native executor. Require
  a shared atomic quota and return only a complete, currently authorized
  BulkResponse under the original request's replay policy.
