package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-identity/delivery"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
)

func TestPublicAdmissionRejectsZeroDependencies(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if service, err := deliverypostgres.NewEnqueueService(ctx, nil, deliverypostgres.EnqueueConfig{}, nil, nil, nil); service != nil || !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("invalid composition accepted", err)
		}
		for _, service := range []*deliverypostgres.EnqueueService{nil, {}} {
			result, err := service.Enqueue(ctx, deliverypostgres.EnqueueCommandRequest{})
			if !errors.Is(err, delivery.ErrInvalidInput) || result.State != delivery.CommitNotCommitted || result.Queued || result.IntentID != "" {
				t.Fatal("invalid service fabricated admission", err)
			}
			status, err := service.StatusGet(ctx, delivery.StatusGetRequest{}, "", authorization.DecisionContext{})
			if !errors.Is(err, delivery.ErrInvalidInput) || status != (delivery.StatusGetResult{}) {
				t.Fatal("invalid service fabricated status", err)
			}
			cancelled, err := service.Cancel(ctx, deliverypostgres.CancelCommandRequest{})
			if !errors.Is(err, delivery.ErrInvalidInput) || cancelled != (delivery.CancelResult{}) {
				t.Fatal("invalid service fabricated cancellation", err)
			}
		}
	}
}

func TestPublicAdmissionDiagnosticsRedactSensitiveInput(t *testing.T) {
	request := deliverypostgres.EnqueueCommandRequest{IdempotencyKey: "private-request-key", Message: delivery.Message{Variables: []delivery.TemplateVariable{{Name: "code", CodeValue: "private-template-value"}}}}
	config := deliverypostgres.EnqueueConfig{Custody: deliverypostgres.ContributorConfig{Deployment: "private-deployment"}, NamespaceKey: [32]byte{7}}
	cancellation := deliverypostgres.CancelCommandRequest{Request: delivery.CancelRequest{Reason: "private-template-value"}}
	for _, value := range []any{request, &request, cancellation, &cancellation, config, &config, deliverypostgres.EnqueueService{}, &deliverypostgres.EnqueueService{}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			assertAdmissionRedacted(t, fmt.Sprintf(verb, value))
		}
		if _, err := json.Marshal(value); !errors.Is(err, delivery.ErrSerializationForbidden) {
			t.Fatal("sensitive admission serialized", err)
		}
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		logger.Info("admission", "value", value)
		assertAdmissionRedacted(t, output.String())
	}
}

func assertAdmissionRedacted(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{"private-request-key", "private-template-value", "private-deployment"} {
		if strings.Contains(text, secret) {
			t.Fatal("sensitive admission diagnostic leaked")
		}
	}
	if !strings.Contains(text, "redacted") {
		t.Fatal("admission diagnostic lacks redaction marker")
	}
}
