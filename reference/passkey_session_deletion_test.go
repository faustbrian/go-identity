package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
)

func TestPasskeySessionDeletionRetainsSelectionAndGraphLifetime(t *testing.T) {
	for name, owner := range map[string]*PasskeyService{
		"nil": nil, "zero": {},
		"unselected": {state: &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant"}}}},
		"closed":     {state: &storeState{closed: true, features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", sessionDeletion: &native.SessionDeletionService{}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := owner.SessionDeletion(); err == nil || got != nil {
				t.Fatal("unselected/closed graph exposed session removal")
			}
		})
	}
	state := &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", sessionDeletion: &native.SessionDeletionService{}}}}
	owner := &PasskeyService{state: state}
	removal, err := owner.SessionDeletion()
	if err != nil {
		t.Fatal("selected pre-initialization handle unavailable", err)
	}
	deny := func(service *PasskeySessionDeletionService, ctx context.Context) {
		t.Helper()
		if out, err := service.DeleteOptions(ctx, passkey.SessionDeleteOptionsRequest{}); err == nil || out.CommandID != "" {
			t.Fatal("uninitialized/closed graph emitted removal assertion")
		}
		if _, err := service.Delete(ctx, passkey.SessionDeleteCompletion{}); err == nil {
			t.Fatal("uninitialized/closed graph removed a key")
		}
		if _, err := service.RecoverDelete(ctx, passkey.SessionDeleteRequest{}, identity.RecoveryQuery{}); err == nil {
			t.Fatal("uninitialized/closed graph disclosed removal metadata")
		}
	}
	deny(nil, t.Context())
	deny(removal, nil)
	deny(removal, context.Background())
	state.features.ready, state.closed = true, true
	deny(removal, t.Context())
	if state.active != 0 {
		t.Fatal("denied operations leaked graph admission")
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{PasskeySessionDeletionConfiguration{Transport: session.CredentialCookie}, *removal} {
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("graph JSON privacy sentinel changed")
		}
		if _, err := value.MarshalText(); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("graph text privacy sentinel changed")
		}
		if !strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), "redacted") {
			t.Fatal("graph diagnostic privacy absent")
		}
	}
}
