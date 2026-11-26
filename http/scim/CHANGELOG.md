# Changelog

## Unreleased

- Select SCIM Bulk and matching discovery over one native executor. Require
  a shared atomic quota and return only a complete, currently authorized
  BulkResponse under the original request's replay policy.
