# Organization HTTP consumer tests

This non-releasable test module retains the genuine invitation send, encrypted
delivery, once-only acceptance and authorized-read journeys. Separating its
Reference/PostgreSQL fixture dependencies keeps production Reference composition
acyclic. All domain behavior is exercised through authenticated public modules;
there are no local replacements or substitute stores.

Use Go 1.27 and task-owned caches. Set `GOLIB_ORGANIZATION_TEST_POSTGRES_DSN` to
an isolated disposable local PostgreSQL server, then run:

```sh
GOWORK=off go test -race -tags=integration -run '^TestInvitation.*GenuineHTTPConsumer$' -count=1 .
GOWORK=off go vet -tags=integration ./...
```

The fixture creates and removes its own database. Only delivery and outbound
HIBP provider seams are controlled. This module is not an application adapter
and exports no runtime feature.
