// Package sessionvalkey owns an optional encrypted positive projection of native
// session admission. PostgreSQL and the session codec retain all authentication,
// authority, expiry and revocation responsibility; Valkey never issues sessions.
package sessionvalkey
