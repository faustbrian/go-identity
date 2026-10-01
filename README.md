# identity

Composable backend identity-domain ownership for Golib. This module is under
development; current implemented slices are subject/pre-authentication ID
contracts and structural user/status-policy validation. Lifecycle commands,
repositories, authorization policies, hooks, directory import and privacy
workflows are not implemented yet.

## Quick start

```go
id, err := identity.NewSubjectID()
if err != nil {
    return err
}
wire := identity.FormatSubjectID(id)
restored, err := identity.ParseSubjectID(wire)
```

The compiled examples demonstrate persisted-value reconstruction. See
[ID semantics](docs/identifiers.md) for API, adoption, security, operations,
tradeoffs and FAQ. This is not a complete login service or administrative UI.
See [user and lifecycle policy](docs/users.md) for structural validation and
transition constraints, including their distinction from authority and writes.

## Development verification

Run Go commands with a task-owned disposable `GOCACHE` and delete it afterwards.
The current focused checks are `go test -race ./...`, `go vet ./...`, and
`go test -run '^$' -fuzz '^FuzzIDParsing$' -fuzztime=10s .`.
Comprehensive module/release gates remain pending during implementation.

## License

[MIT](LICENSE).
