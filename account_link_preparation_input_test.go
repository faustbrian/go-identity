package identity_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestAccountLinkPreparationInputKeepsRootScopeWithoutSubjectOrLinkProof(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser,
		OperationID: "identity.account.link-token", PolicyID: "policy", PolicyVersion: 1, SchemaID: "identity-account", SchemaVersion: 1,
		CorrelationID: "correlation", RecordID: "account-a", LinkMode: identity.AccountLinkExplicit}
	spec := identity.AccountLinkPreparationCommand{Binding: binding, ProviderID: "configured-oidc", ProviderConfigVersion: 1,
		FlowID: "flow-a", FlowFingerprint: [32]byte{1}, SessionID: "session-a", SessionVersion: 1,
		Counters: identity.AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: time.Unix(1000, 0).UTC(), KeyVersions: []uint32{7}}}
	code := []byte("synthetic-code+/= :opaque")
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	callback, err := identity.NewOAuthCallbackInput(code, state, identity.OAuthCallbackLimits{MaxCodeBytes: 16384, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(callback.Destroy)
	cookie := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	command, err := identity.NewAccountLinkPreparationCommand(spec, callback, cookie)
	if err != nil {
		t.Fatal(err)
	}
	got, owned, bearer, ok := command.AccountLinkPreparationInput()
	if !ok || !reflect.DeepEqual(got, spec) || bearer.Token() != cookie.Token() {
		t.Fatal("preparation changed original root/provider/flow/session intent")
	}
	got.Counters.KeyVersions[0] = 99
	again, _, _, ok := command.AccountLinkPreparationInput()
	if !ok || again.Counters.KeyVersions[0] != 7 {
		t.Fatal("preparation exposes mutable counter intent")
	}
	if _, ok := command.LinkAccount(); ok {
		t.Fatal("preparation became a signed link command")
	}
	if _, _, ok := command.AccountLinkCounterCommand(); ok {
		t.Fatal("preparation bypassed generated link proof")
	}
	if _, ok := command.Feature(); ok {
		t.Fatal("root link preparation became a generic feature")
	}
	if err := owned.Use(context.Background(), func(_ context.Context, actualCode, actualState []byte) error {
		if !bytes.Equal(actualCode, code) || string(actualState) != state {
			t.Fatal("callback input normalized or replaced original exchange bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{command, callback} {
		text := fmt.Sprintf("%#v %v %s", value, value, value)
		if strings.Contains(text, string(code)) || strings.Contains(text, state) || strings.Contains(text, cookie.Token()) {
			t.Fatal("callback custody leaked through diagnostics")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("callback custody permits accidental serialization")
		}
	}
	callback.Destroy()
	if err := owned.Use(context.Background(), func(context.Context, []byte, []byte) error {
		t.Fatal("destroyed callback custody remained readable")
		return nil
	}); err == nil {
		t.Fatal("destroyed callback custody was accepted")
	}
}

func TestOAuthCallbackBorrowIsExactAndClearedOnEveryExit(t *testing.T) {
	for _, exit := range []string{"success", "error", "panic", "destroy"} {
		t.Run(exit, func(t *testing.T) {
			input, err := identity.NewOAuthCallbackInput([]byte("original-code"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 64, StateBytes: 32})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(input.Destroy)
			var borrowedCode, borrowedState []byte
			cause := errors.New("synthetic-private-callback-data")
			err = input.Use(context.Background(), func(ctx context.Context, code, state []byte) error {
				if cap(code) != len(code) || cap(state) != len(state) {
					t.Fatal("borrow exposes uncleared spare capacity")
				}
				borrowedCode, borrowedState = code, state
				if err := input.Use(ctx, func(context.Context, []byte, []byte) error { t.Fatal("reentrant callback admitted"); return nil }); !errors.Is(err, identity.ErrInvalidOAuthCallbackInput) {
					t.Fatal("reentrant use did not fail closed")
				}
				switch exit {
				case "error":
					return cause
				case "panic":
					panic(cause)
				case "destroy":
					input.Destroy()
				}
				return nil
			})
			if exit == "error" && (!errors.Is(err, cause) || strings.Contains(fmt.Sprintf("%#v %v %s", err, err, err), cause.Error())) {
				t.Fatal("callback classification lost or private error disclosed")
			}
			if exit == "panic" && !errors.Is(err, identity.ErrInvalidOAuthCallbackInput) {
				t.Fatal("panic was not redacted")
			}
			if (exit == "success" || exit == "destroy") && err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(borrowedCode, make([]byte, len(borrowedCode))) || !bytes.Equal(borrowedState, make([]byte, len(borrowedState))) {
				t.Fatal("callback borrow survives exit")
			}
			if exit == "destroy" && input.Use(context.Background(), func(context.Context, []byte, []byte) error { t.Fatal("destruction was not terminal"); return nil }) == nil {
				t.Fatal("destroyed owner usable")
			}
		})
	}
}

func TestAccountLinkPreparationRejectsUnsupportedOrIncompleteScope(t *testing.T) {
	binding := identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAABA", TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser,
		OperationID: "identity.account.link-token", PolicyID: "policy", PolicyVersion: 1, SchemaID: "identity-account", SchemaVersion: 1,
		CorrelationID: "correlation", RecordID: "account-a", LinkMode: identity.AccountLinkExplicit}
	base := identity.AccountLinkPreparationCommand{Binding: binding, ProviderID: "oidc", ProviderConfigVersion: 1, FlowID: "flow-a", FlowFingerprint: [32]byte{1}, SessionID: "session-a", SessionVersion: 1,
		Counters: identity.AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: time.Unix(1000, 0).UTC(), KeyVersions: []uint32{7}}}
	input, err := identity.NewOAuthCallbackInput([]byte("code"), base64.RawURLEncoding.EncodeToString(make([]byte, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 64, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	bearer := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	for _, mutate := range []func(*identity.AccountLinkPreparationCommand){
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.CommandID = "invalid" },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.TenantID = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.UserID = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.ActorID = "other-user" },
		func(s *identity.AccountLinkPreparationCommand) {
			s.Binding.ActorKind = authorization.SubjectServiceAccount
		},
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.OperationID = "identity.account.unlink" },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.RecordID = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.LinkMode = identity.AccountLinkImplicit },
		func(s *identity.AccountLinkPreparationCommand) {
			s.Binding.LinkMode = identity.AccountLinkAdministrative
		},
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.PolicyVersion = 0 },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.SchemaID = "other" },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.SchemaVersion = 2 },
		func(s *identity.AccountLinkPreparationCommand) { s.Binding.AnonymousFlowID = "flow-b" },
		func(s *identity.AccountLinkPreparationCommand) { s.ProviderID = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.ProviderConfigVersion = 0 },
		func(s *identity.AccountLinkPreparationCommand) { s.FlowID = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.FlowFingerprint = [32]byte{} },
		func(s *identity.AccountLinkPreparationCommand) { s.SessionID = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.SessionVersion = 0 },
		func(s *identity.AccountLinkPreparationCommand) { s.Counters.Network = "" },
		func(s *identity.AccountLinkPreparationCommand) { s.Counters.PreparedAt = time.Time{} },
		func(s *identity.AccountLinkPreparationCommand) { s.Counters.KeyVersions = []uint32{7, 7} },
	} {
		spec := base
		mutate(&spec)
		command, err := identity.NewAccountLinkPreparationCommand(spec, input, bearer)
		if err == nil {
			t.Fatal("unsupported original scope admitted")
		}
		if _, _, _, ok := command.AccountLinkPreparationInput(); ok {
			t.Fatal("failed construction returned usable intent")
		}
	}
	for _, bad := range []authentication.BearerCredential{{}, authentication.NewBearerCredential("code"), authentication.NewBearerCredential(bearer.Token() + "=")} {
		if _, err := identity.NewAccountLinkPreparationCommand(base, input, bad); err == nil {
			t.Fatal("invalid session transport accepted")
		}
	}
	command, err := identity.NewAccountLinkPreparationCommand(base, input, bearer)
	if err != nil {
		t.Fatal(err)
	}
	base.Counters.KeyVersions[0] = 99
	got, _, _, ok := command.AccountLinkPreparationInput()
	if !ok || got.Counters.KeyVersions[0] != 7 {
		t.Fatal("caller mutation changed frozen intent")
	}
	input.Destroy()
	if _, err := identity.NewAccountLinkPreparationCommand(base, input, bearer); err == nil {
		t.Fatal("destroyed callback admitted to preparation")
	}
	if _, _, _, ok := (identity.Command{}).AccountLinkPreparationInput(); ok {
		t.Fatal("zero command has preparation custody")
	}
}
