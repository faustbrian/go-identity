//go:build integration

package reference_test

import "testing"

// A real fresh PostgreSQL-only graph must prove the full original HTTP journey
// and its rollback/replay/CSRF/isolation checks without backdating risk history.
func TestReferencePostgresBaseline(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true})
}
