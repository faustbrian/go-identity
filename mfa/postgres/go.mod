module github.com/faustbrian/go-identity/mfa/postgres

go 1.27.0

require (
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.1-0.20261003012155-21ad3d11d3b2
	github.com/faustbrian/go-authentication v1.2.2-0.20261009190006-7fc797d91317
	github.com/faustbrian/go-authorization v1.1.1-0.20261005011349-60ed4b3229d8
	github.com/faustbrian/go-capability v1.0.1-0.20261010235105-f1b4eb9d0c3a
	github.com/faustbrian/go-capability/postgres/identity v0.0.0-20261012193534-c13f373468a4
	github.com/faustbrian/go-clock v1.0.0
	github.com/faustbrian/go-identity v0.0.0-20261011052554-3ca77f9f25c7
	github.com/faustbrian/go-identity/delivery v0.0.0-20261004192212-c70512ebfb31
	github.com/faustbrian/go-identity/delivery/postgres v0.0.0-20261010105848-0aa2a90aed7e
	github.com/faustbrian/go-identity/mfa v0.0.0-20261011052926-b536d4810e2e
	github.com/faustbrian/go-identity/postgres v0.0.0-20261011211824-adb09143da63
	github.com/faustbrian/go-identity/risk v0.0.0-20261011090203-f68ad28f8fdb
	github.com/faustbrian/go-identity/risk/postgres v0.0.0-20261010202342-98173b7fb0ac
	github.com/faustbrian/go-identity/session v0.0.0-20261011102605-954333fbc307
	github.com/faustbrian/go-migrations/v3 v3.0.2-0.20261008154303-7eabbeb156f8
	github.com/faustbrian/go-password v1.0.1-0.20261001082808-a3dbd862340c
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-secret-envelope v1.0.0
	github.com/faustbrian/go-transactional-outbox/v2 v2.0.0-20261002184451-72a9fe57a638
	github.com/faustbrian/go-transactional-outbox/v2/postgres/identity v0.0.0-20261002184451-72a9fe57a638
	github.com/jackc/pgx/v5 v5.10.0
)
