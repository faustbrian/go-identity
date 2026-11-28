module github.com/faustbrian/go-identity/impersonation/postgres

go 1.27.0

require (
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.2-0.20261015062502-d62df280d85e
	github.com/faustbrian/go-authentication/v2 v2.0.2-0.20261015052822-d9f5132c7f68
	github.com/faustbrian/go-authorization/v3 v3.0.1-0.20261015052455-a55bbebb1060
	github.com/faustbrian/go-clock v1.2.0
	github.com/faustbrian/go-identity v0.0.0-20261123113741-94b876278a93
	github.com/faustbrian/go-identity/impersonation v0.0.0-20261128060409-ec2ff88687be
	github.com/faustbrian/go-identity/mfa/postgres v0.0.0-20261128064753-40cd49f6dbc8
	github.com/faustbrian/go-identity/postgres v0.0.0-20261128062444-5bbc0f7c1e0a
	github.com/faustbrian/go-identity/risk v0.0.0-20261124125401-3845f97fe8aa
	github.com/faustbrian/go-identity/risk/postgres v0.0.0-20261124125758-d8bd5f7b074a
	github.com/faustbrian/go-identity/session v0.0.0-20261126235901-19a81db3fa1c
	github.com/faustbrian/go-identity/session/postgres v0.0.0-20261128060844-611ac945c9dd
	github.com/faustbrian/go-migrations/v3 v3.1.1-0.20261015110643-ca105f265cfc
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-secret-envelope/v2 v2.0.1
	github.com/faustbrian/go-transactional-outbox/postgres/identity v0.0.0-20261015064732-3aaa84f79f74
	github.com/faustbrian/go-transactional-outbox/v2 v2.0.2-0.20261015062550-37ea15436ae9
	github.com/jackc/pgx/v5 v5.11.0
)

require (
	github.com/faustbrian/go-capability/v2 v2.0.2-0.20261015044219-caab644d2fec // indirect
	github.com/faustbrian/go-identity/delivery v0.0.0-20261015061706-1f0b46ab1053 // indirect
	github.com/faustbrian/go-identity/delivery/postgres v0.0.0-20261015104034-f16881100907 // indirect
	github.com/faustbrian/go-identity/mfa v0.0.0-20261025081547-dcd89dfc3e34 // indirect
	github.com/faustbrian/go-migrations/v2 v2.0.0 // indirect
	github.com/faustbrian/go-password/v2 v2.0.2-0.20261015050515-4eb0fefa60ff // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
