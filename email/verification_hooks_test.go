package email_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

type verificationHook struct {
	before func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error)
	after  func(context.Context, identity.AfterHookInput) error
}

func (h verificationHook) Before(ctx context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
	if h.before != nil {
		return h.before(ctx, in)
	}
	return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
}
func (h verificationHook) After(ctx context.Context, in identity.AfterHookInput) error {
	if h.after != nil {
		return h.after(ctx, in)
	}
	return nil
}

func verificationHookBinding(t *testing.T) identity.CommandBinding {
	t.Helper()
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return identity.CommandBinding{CommandID: command, TenantID: "tenant", UserID: "01K70ZJ34CWYGBDM2PWQX65QJ5", ActorID: "ingress", ActorKind: authorization.SubjectServiceAccount, RecordID: "01K70ZJ34CWYGBDM2PWQX65QJ6", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.native-v1", SchemaVersion: 1, PolicyID: "verification", PolicyVersion: 1, CorrelationID: string(command)}
}

func TestVerificationHooksExposeOnlyImmutableReadOnlyCorrelation(t *testing.T) {
	b := verificationHookBinding(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var phases []string
	hooks, err := email.NewVerificationHooks([]identity.Hook{verificationHook{
		before: func(_ context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
			phases = append(phases, "before")
			if in.Context != (identity.OperationContext{OperationID: b.OperationID, TenantID: b.TenantID, ActorID: b.ActorID, CorrelationID: b.CorrelationID, Deadline: deadline}) {
				t.Fatal("original correlation changed")
			}
			want := []string{"command_id", "user_id", "identifier_id"}
			values := []string{string(b.CommandID), string(b.UserID), b.RecordID}
			if len(in.Fields) != len(want) {
				t.Fatal("unexpected metadata disclosure")
			}
			for i, field := range in.Fields {
				if field.Name != want[i] || field.Value.Kind != identity.AttributeString || field.Value.String != values[i] || field.Sensitivity != identity.SensitivitySensitive {
					t.Fatal("incorrect correlation field")
				}
			}
			return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
		},
		after: func(_ context.Context, in identity.AfterHookInput) error {
			phases = append(phases, "after")
			if in.Observation.Outcome != identity.AttemptedCommitOutcomeCommitted || in.Observation.Notes == nil || len(in.Observation.Notes) != 0 {
				t.Fatal("unexpected commit observation")
			}
			return nil
		},
	}}, email.VerificationHooksConfig{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = hooks.Before(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err = hooks.After(ctx, b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(phases, []string{"before", "after"}) {
		t.Fatal("phase selection lost")
	}
}

func TestVerificationHooksRejectEnrichmentAndExplicitPolicyDenial(t *testing.T) {
	for _, variant := range []string{"reject", "enrich", "error", "panic"} {
		t.Run(variant, func(t *testing.T) {
			hooks, err := email.NewVerificationHooks([]identity.Hook{verificationHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
				switch variant {
				case "reject":
					return identity.BeforeHookResult{Decision: identity.BeforeHookReject}, nil
				case "error":
					return identity.BeforeHookResult{}, errors.New("private callback details")
				case "panic":
					panic("private callback details")
				default:
					return identity.BeforeHookResult{Decision: identity.BeforeHookContinue, Enrichments: []identity.HookEnrichment{{Fields: []identity.HookField{{Name: "user_id", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "replacement"}, Sensitivity: identity.SensitivitySensitive}}}}}, nil
				}
			}}}, email.VerificationHooksConfig{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if err = hooks.Before(t.Context(), verificationHookBinding(t)); err == nil {
				t.Fatal("unsafe callback admitted")
			}
			if variant == "reject" && !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("explicit denial lost", err)
			}
		})
	}
}

func TestVerificationHooksDenyOtherWorkflowAndMalformedBindingsBeforeCallbacks(t *testing.T) {
	calls := 0
	hooks, err := email.NewVerificationHooks([]identity.Hook{verificationHook{before: func(context.Context, identity.BeforeHookInput) (identity.BeforeHookResult, error) {
		calls++
		return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
	}, after: func(context.Context, identity.AfterHookInput) error { calls++; return nil }}}, email.VerificationHooksConfig{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.OperationID = "identity.email.change-confirm" },
		func(b *identity.CommandBinding) { b.SchemaID = "other" },
		func(b *identity.CommandBinding) { b.UserID = "" },
		func(b *identity.CommandBinding) { b.RecordID = "" },
	} {
		b := verificationHookBinding(t)
		mutate(&b)
		if hooks.Before(t.Context(), b) == nil || hooks.After(t.Context(), b) == nil {
			t.Fatal("foreign hook workflow admitted")
		}
	}
	if calls != 0 {
		t.Fatal("malformed operation reached callbacks")
	}
}
