module github.com/faustbrian/go-identity/otp/postgres

go 1.27.0

require (
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.1-0.20261003012155-21ad3d11d3b2
	github.com/faustbrian/go-transactional-outbox/v2/postgres/identity v0.0.0-20261002184451-72a9fe57a638
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-authentication v1.2.2-0.20261006180804-0f9f7eac1f1d
	github.com/faustbrian/go-authorization v1.1.1-0.20261005011349-60ed4b3229d8
	github.com/faustbrian/go-identity v0.0.0-20261007092517-8969d596e5c8
	github.com/faustbrian/go-identity/delivery v0.0.0-20261004192212-c70512ebfb31
	github.com/faustbrian/go-identity/delivery/postgres v0.0.0-20261007103133-8316d8af9fd7
	github.com/faustbrian/go-identity/otp v0.0.0-20261009042249-1003a22dcc75
	github.com/faustbrian/go-identity/postgres v0.0.0-20261009040149-a18ab1f670f9
	github.com/faustbrian/go-identity/risk v0.0.0-20261008072308-b2d88e4d68db
	github.com/faustbrian/go-identity/session v0.0.0-20261008195308-9e9b25864d55
	github.com/faustbrian/go-identity/session/postgres v0.0.0-20261008202327-7a2bc6e3a5d0
	github.com/faustbrian/go-migrations/v3 v3.0.2-0.20261001014304-a461b18b6b24
	github.com/faustbrian/go-secret-envelope v1.0.1-0.20260913112010-22fc4a2d925d
	github.com/jackc/pgx/v5 v5.10.0
)
