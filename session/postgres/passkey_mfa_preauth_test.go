package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestMFAPasskeyPreAuthRequiresProtectedCompletion(t *testing.T) {
	canceled, stop := context.WithCancel(t.Context())
	stop()
	for _, ctx := range []context.Context{nil, t.Context(), canceled} {
		if err := ReserveMFAPasskeyPreAuth(ctx, kernel.Work{}, nil, identity.Command{}, Config{}, session.PreAuthTransaction{}); err == nil {
			t.Fatal("unowned completion reserved a browser")
		}
		if err := FinalizeMFAPasskeyPreAuth(ctx, kernel.Work{}, nil, identity.Command{}, Config{}, session.PreAuthTransaction{}); err == nil {
			t.Fatal("unowned completion consumed a browser")
		}
	}
	if err := ReserveMFAPasskeyPreAuth(canceled, kernel.Work{}, nil, identity.Command{}, Config{}, session.PreAuthTransaction{}); !errors.Is(err, context.Canceled) {
		t.Fatal("browser reservation discarded cancellation")
	}
	if err := FinalizeMFAPasskeyPreAuth(canceled, kernel.Work{}, nil, identity.Command{}, Config{}, session.PreAuthTransaction{}); !errors.Is(err, context.Canceled) {
		t.Fatal("browser completion discarded cancellation")
	}
}

func TestMFAPasskeyPreAuthRelationDoesNotWidenGenericConsumption(t *testing.T) {
	command, _ := passkeyMFAProjectionFixture(t, false)
	f, _ := testPreAuth(t, time.Now().UTC()).Bindings()
	f.Binding.ID = identity.PreAuthTransactionID(command.Binding.AnonymousFlowID)
	f.Binding.Intent.TenantID = command.Binding.TenantID
	f.Binding.Intent.PolicyVersion = command.Binding.PolicyVersion
	f.Binding.Intent.PolicyID = "original-passkey-policy"
	f.Binding.Intent.Action = "identity.passkey.signin-verify"
	use := PreAuthUse{Command: command.Binding, Fingerprint: [32]byte{1}, Generation: 1}
	if !validMFAPasskeyPreAuthUse(use, f) || use.valid(f) {
		t.Fatal("explicit continuation relation was absent or widened generic admission")
	}
	for _, mutate := range []func(*PreAuthUse, *session.PreAuthTransactionSpec){
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) {
			u.Command.OperationID = "identity.mfa.otp-verify"
		},
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Command.SchemaID = "mfa-totp-step-up" },
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Command.UserID = "other-user" },
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Command.TenantID = "other-tenant" },
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Command.PolicyVersion++ },
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Command.AnonymousFlowID = "other-flow" },
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Generation = 0 },
		func(u *PreAuthUse, _ *session.PreAuthTransactionSpec) { u.Fingerprint = [32]byte{} },
		func(_ *PreAuthUse, f *session.PreAuthTransactionSpec) {
			f.Binding.Intent.Action = "identity.password.signin"
		},
		func(_ *PreAuthUse, f *session.PreAuthTransactionSpec) {
			f.Binding.Intent.Purpose = session.PreAuthPhonePasswordRecovery
		},
	} {
		candidate, flow := use, f
		mutate(&candidate, &flow)
		if validMFAPasskeyPreAuthUse(candidate, flow) {
			t.Fatal("foreign continuation relation admitted browser consumption")
		}
	}
}
