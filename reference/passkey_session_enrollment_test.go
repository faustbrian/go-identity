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

func TestPasskeySessionEnrollmentRetainsSelectionAndGraphLifetime(t *testing.T) {
	for name, owner := range map[string]*PasskeyService{
		"nil":        nil,
		"zero":       {},
		"unselected": {state: &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant"}}}},
		"closed":     {state: &storeState{closed: true, features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", sessionEnrollment: &native.SessionEnrollmentService{}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := owner.SessionEnrollment(); err == nil || got != nil {
				t.Fatal("unselected/closed graph exposed session enrollment")
			}
		})
	}
	state := &storeState{features: &featureState{composed: true, passkey: &passkeyState{tenant: "tenant", sessionEnrollment: &native.SessionEnrollmentService{}}}}
	owner := &PasskeyService{state: state}
	enrollment, err := owner.SessionEnrollment()
	if err != nil {
		t.Fatal("selected pre-initialization enrollment handle unavailable", err)
	}
	deny := func(ctx context.Context) {
		t.Helper()
		if out, err := enrollment.EnrollmentAssertionOptions(ctx, passkey.SessionEnrollmentOptionsRequest{}); err == nil || out.CommandID != "" {
			t.Fatal("uninitialized/closed graph emitted enrollment assertion")
		}
		if out, err := enrollment.RegistrationOptions(ctx, passkey.SessionEnrollmentAuthorization{}); err == nil || out.CommandID != "" {
			t.Fatal("uninitialized/closed graph authorized enrollment")
		}
		if out, expiry, err := enrollment.RegistrationOptionsForDelivery(ctx, passkey.SessionEnrollmentAuthorization{}); err == nil || out.CommandID != "" || !expiry.IsZero() {
			t.Fatal("uninitialized/closed graph disclosed delivery ceiling")
		}
		if _, err := enrollment.Register(ctx, passkey.SessionEnrollmentCompletion{}); err == nil {
			t.Fatal("uninitialized/closed graph enrolled key")
		}
		if out, err := enrollment.SessionRegistrationRateSource(ctx, passkey.SessionEnrollmentRequest{}, ""); err == nil || out != (passkey.CeremonyRateSource{}) {
			t.Fatal("uninitialized/closed graph disclosed enrollment rate source")
		}
	}
	deny(nil)
	deny(context.Background())
	state.features.ready, state.closed = true, true
	deny(t.Context())
	if state.active != 0 {
		t.Fatal("denied operations leaked graph admission")
	}
	for _, value := range []interface {
		MarshalJSON() ([]byte, error)
		MarshalText() ([]byte, error)
	}{PasskeySessionEnrollmentConfiguration{Transport: session.CredentialCookie}, *enrollment} {
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
	var absent *PasskeySessionEnrollmentService
	if _, err := absent.EnrollmentAssertionOptions(t.Context(), passkey.SessionEnrollmentOptionsRequest{}); err == nil {
		t.Fatal("nil handle emitted enrollment assertion")
	}
	if _, err := absent.RegistrationOptions(t.Context(), passkey.SessionEnrollmentAuthorization{}); err == nil {
		t.Fatal("nil handle emitted registration options")
	}
	if out, expiry, err := absent.RegistrationOptionsForDelivery(t.Context(), passkey.SessionEnrollmentAuthorization{}); err == nil || out.CommandID != "" || !expiry.IsZero() {
		t.Fatal("nil handle disclosed registration delivery ceiling")
	}
	if _, err := absent.Register(t.Context(), passkey.SessionEnrollmentCompletion{}); err == nil {
		t.Fatal("nil handle enrolled credential")
	}
	if out, err := absent.SessionRegistrationRateSource(t.Context(), passkey.SessionEnrollmentRequest{}, ""); err == nil || out != (passkey.CeremonyRateSource{}) {
		t.Fatal("nil handle disclosed enrollment source")
	}
}
