package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/faustbrian/go-identity/delivery"
	deliverypostgres "github.com/faustbrian/go-identity/delivery/postgres"
)

func TestPublicReceiptRequiresSelectedOwnedComposition(t *testing.T) {
	for _, service := range []*deliverypostgres.EnqueueService{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			out, err := service.RecordReceipt(ctx, deliverypostgres.ReceiptCommandRequest{})
			if !errors.Is(err, delivery.ErrInvalidInput) || out != (delivery.ReceiptRecordResult{}) {
				t.Fatal("invalid composition fabricated receipt", err)
			}
		}
	}
}

func TestPublicReceiptDiagnosticsRedactCallbackCustody(t *testing.T) {
	key := deliverypostgres.ReceiptKeyProfile{KeyID: "private-request-key", Key: [32]byte{9}}
	cfg := deliverypostgres.ReceiptAuthenticationConfig{Profiles: []deliverypostgres.ReceiptKeyProfile{key}}
	callback := deliverypostgres.SignedReceiptCallback{Body: []byte("private-template-value"), Signature: [32]byte{9}}
	request := deliverypostgres.ReceiptCommandRequest{Callback: callback}
	for _, value := range []any{key, &key, cfg, &cfg, callback, &callback, request, &request} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			assertAdmissionRedacted(t, fmt.Sprintf(verb, value))
		}
		if _, err := json.Marshal(value); !errors.Is(err, delivery.ErrSerializationForbidden) {
			t.Fatal("callback custody serialized", err)
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("receipt", "value", value)
		assertAdmissionRedacted(t, buf.String())
	}
}
