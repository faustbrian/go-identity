package impersonationpostgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestImpersonationServiceRedactsRuntimeKeys(t *testing.T) {
	service := &Service{config: Config{Coordinator: kernel.CoordinatorConfig{
		RetainedFingerprintKeys: map[uint32][32]byte{1: {19, 31, 59}},
	}}}
	for _, input := range []any{service, *service} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if got := fmt.Sprintf(format, input); got != "impersonation.Service(redacted)" {
				t.Fatalf("service formatting exposed runtime graph with %s", format)
			}
		}
		if _, err := json.Marshal(input); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("runtime service graph allowed JSON serialization")
		}
	}
}

func TestUnconfiguredServiceNeverPreparesOrExecutesApproval(t *testing.T) {
	ctx := t.Context()
	service, err := NewService(nil, Config{})
	if service != nil || !errors.Is(err, impersonation.ErrInvalidInput) {
		t.Fatal("constructed a service without a primary or authority owners", err)
	}
	if command, err := service.PrepareRequest(ctx, RequestInput{}); !errors.Is(err, impersonation.ErrInvalidInput) || command.state != nil {
		t.Fatal("unconfigured service prepared a request", err)
	}
	if command, err := service.PrepareApproval(ctx, ApproveInput{}); !errors.Is(err, impersonation.ErrInvalidInput) || command.state != nil {
		t.Fatal("unconfigured service prepared an approval", err)
	}
	if result, err := service.Execute(ctx, PreparedCommand{}); !errors.Is(err, impersonation.ErrInvalidInput) || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("unowned input received a committed outcome", err)
	}
}
