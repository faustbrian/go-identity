package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	database "github.com/faustbrian/go-postgres"
)

type untouchedSender struct{}

func (untouchedSender) Send(context.Context, delivery.Attempt) (delivery.DeliveryResult, error) {
	panic("provider invoked during construction")
}

func TestBaselinePublicGraphConstructionDoesNotActivateTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	credentials, err := loadCredentials(directory, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pool, err := database.New(ctx, database.Config{DSN: "host=127.0.0.1 port=1 user=unused dbname=unused sslmode=disable search_path=public", MaxConns: 4, StartupPolicy: database.StartupLazy})
	if err != nil {
		t.Fatal("lazy pool construction failed")
	}
	defer pool.Close(context.Background())
	selected, err := parseOptions([]string{"serve", "--local-capture", "--directory", directory, "--dsn-file", "private-dsn"})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := buildBaseline(ctx, selected, credentials, pool, untouchedSender{})
	if err != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatal("supported public graph construction failed", invalid.Field)
		}
		t.Fatal("supported public graph construction failed", err)
	}
	defer graph.close(context.Background())
	if graph.server.Readiness(ctx).Ready {
		t.Fatal("uninitialized graph accepts traffic")
	}
	selectedOperations := make(map[string]bool)
	for _, operation := range graph.server.OpenAPI().Operations() {
		selectedOperations[operation.Record.OperationID] = true
	}
	for _, operation := range []string{"identity.password.signup", "identity.email.verification-confirm", "identity.password.signin", "identity.session.get", "identity.session.signout"} {
		if !selectedOperations[operation] {
			t.Fatal("selected baseline operation absent", operation)
		}
	}
	for _, operation := range []string{"identity.password.reset-complete", "identity.password.change", "identity.otp.signin", "identity.mfa.totp-verify"} {
		if selectedOperations[operation] {
			t.Fatal("unselected authentication feature exposed", operation)
		}
	}
}
