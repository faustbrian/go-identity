package postgres_test

import (
	"testing"

	pg "github.com/faustbrian/go-identity/otp/postgres"
)

// SEND-01: invalid construction fails closed before any borrowed dependency is
// accessed. The actual working caller path is exercised by PostgreSQL tests.
func TestPublicSendRejectsMissingDependencies(t *testing.T) {
	if service, err := pg.NewSendService(nil, pg.SendConfig{}, nil); err == nil || service != nil {
		t.Fatal("incomplete public composition accepted")
	}
}
