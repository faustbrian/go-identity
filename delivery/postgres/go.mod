module github.com/faustbrian/go-identity/delivery/postgres

go 1.27.0

require (
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.1-0.20261003012155-21ad3d11d3b2
	github.com/faustbrian/go-authorization v1.0.1-0.20261001103722-a74c24b38463
	github.com/faustbrian/go-clock v1.0.0
	github.com/faustbrian/go-identity v0.0.0-20261004182158-24b21c46d3ca
	github.com/faustbrian/go-identity/delivery v0.0.0-20261004192212-c70512ebfb31
	github.com/faustbrian/go-identity/postgres v0.0.0-20261004044757-c3d7931906e0
	github.com/faustbrian/go-migrations/v3 v3.0.2-0.20261001014304-a461b18b6b24
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-secret-envelope v1.0.1-0.20260913112010-22fc4a2d925d
	github.com/faustbrian/go-transactional-outbox/v2 v2.0.0-20261002184451-72a9fe57a638
	github.com/faustbrian/go-transactional-outbox/v2/postgres/identity v0.0.0-20261002184451-72a9fe57a638
	github.com/jackc/pgx/v5 v5.10.0
)

require (
	github.com/faustbrian/go-capability v1.0.1-0.20261002040645-174b128867a4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
