package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
)

func TestPasskeySessionManagementRetainsSelectionAndGraphLifetime(t *testing.T) {
	for name, owner := range map[string]*PasskeyService{"nil": nil, "zero": {}, "unselected": {state: &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant"}}}}, "closed": {state: &storeState{closed: true, features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", sessionManagement: &native.SessionManagementService{}}}}}} {
		t.Run(name, func(t *testing.T) {
			if got, err := owner.SessionManagement(); err == nil || got != nil {
				t.Fatal("unselected/closed graph exposed session management")
			}
		})
	}
	state := &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", sessionManagement: &native.SessionManagementService{}}}}
	owner := &PasskeyService{state: state}
	manager, err := owner.SessionManagement()
	if err != nil {
		t.Fatal("selected pre-initialization handle unavailable", err)
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if out, err := manager.UpdateOptions(ctx, passkey.SessionUpdateOptionsRequest{}); err == nil || out.CommandID != "" {
			t.Fatal("uninitialized graph emitted challenge")
		}
		if out, err := manager.Update(ctx, passkey.SessionUpdateCompletion{}); err == nil || out.CommandID != "" || out.Credential != nil {
			t.Fatal("uninitialized graph renamed")
		}
	}
	state.features.ready = true
	state.closed = true
	if _, err := manager.UpdateOptions(t.Context(), passkey.SessionUpdateOptionsRequest{}); err == nil {
		t.Fatal("retained handle bypassed Close")
	}
	if _, err := manager.Update(t.Context(), passkey.SessionUpdateCompletion{}); err == nil {
		t.Fatal("retained handle bypassed Close")
	}
	if state.active != 0 {
		t.Fatal("denied operations leaked graph admission")
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{PasskeySessionManagementConfiguration{Transport: session.CredentialCookie}, *manager} {
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
	var absent *PasskeySessionManagementService
	if _, err := absent.UpdateOptions(t.Context(), passkey.SessionUpdateOptionsRequest{}); err == nil {
		t.Fatal("nil handle emitted options")
	}
	if _, err := absent.Update(t.Context(), passkey.SessionUpdateCompletion{}); err == nil {
		t.Fatal("nil handle mutated")
	}
}
