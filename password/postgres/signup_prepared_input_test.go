package passwordpostgres

import (
	"bytes"
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type signupPreparedInputOwner interface {
	retainSignupInput(context.Context, *envelope.Service, string, kernel.RequestKeyPreparationBinding, [32]byte, identity.CommandBinding, kernel.PasswordRegistrationIntent, session.PreAuthTransaction, identity.RequestIntent, time.Time) ([]byte, error)
	restoreSignupInput(context.Context, *envelope.Service, kernel.RequestKeyPreparationBinding, [32]byte, []byte, identity.RequestIntent) (identity.CommandBinding, kernel.PasswordRegistrationIntent, session.PreAuthTransaction, time.Time, error)
}

type signupInputRecoveryOwner interface {
	recoverSignupInput(context.Context, *envelope.Service, kernel.RequestKeyPreparationBinding, [32]byte, []byte) (identity.CommandBinding, kernel.PasswordRegistrationIntent, session.PreAuthTransaction, time.Time, error)
}

// The original mapping must recover the selected account/defaults/identifier
// without selecting another account or re-running field policy. Changed request
// commitments and authenticated-but-inconsistent structural input must deny.
func TestSignupPreparedInputFreezesOriginalSelectedCreation(t *testing.T) {
	owner, ok := any(&Repository{}).(signupPreparedInputOwner)
	if !ok {
		t.Fatal("native signup cannot retain selected creation in original keyed input")
	}
	r, flow, _, now := nativeSignupFlow(t)
	r.IdempotencyKey, _ = identity.NewIdempotencyKey(bytes.Repeat([]byte{'J'}, 32))
	id, _ := identity.NewCommandID()
	b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, AnonymousFlowID: string(r.PreAuthID), OperationID: "identity.password.signup", SchemaID: "password-signup", SchemaVersion: 1, PolicyID: "login", PolicyVersion: 3, CorrelationID: string(id)}
	k := kernel.RequestKeyPreparationBinding{Namespace: "signup", Scope: kernel.RequestKeyScope{TenantID: b.TenantID, ActorID: b.ActorID, ActorKind: b.ActorKind, Method: "POST", RouteID: b.OperationID}, Admission: kernel.RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: 1}, Feature: kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}, Operation: passwordSignupOperation()}, PolicyVersion: 3, IntentDigest: [32]byte{1}}
	creation := b
	creation.AnonymousFlowID, creation.OperationID, creation.UserID, creation.SchemaID = "", "identity.user.create", "01K70ZJ34CWYGBDM2PWQX65QJ5", "signup-fields"
	selected := kernel.PasswordRegistrationIntent{Creation: identity.CreateUserCommand{Binding: creation, Status: identity.StatusActive, Attributes: []identity.AttributeUpdate{{Name: "name", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "original-default"}}}}}, Identifier: identity.Identifier{ID: "email", UserID: creation.UserID, Kind: identity.IdentifierEmail, CanonicalValue: "person@example.test", DisplayValue: "Person@EXAMPLE.TEST", Version: 1}, Credential: identity.CredentialRef{ID: "password", TenantID: b.TenantID, UserID: creation.UserID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, ComparisonProfile: "email-v1"}
	if _, err := kernel.PasswordRegistrationFields(selected); err != nil {
		t.Fatal("invalid selected creation fixture", err)
	}
	ctx := context.Background()
	profile := [32]byte{2}
	intent, err := (&Repository{}).signupRequestIntent(ctx, r, [32]byte{1}, profile, password.RegistrationPolicy{Enabled: true, MinimumBytes: 8, MaximumBytes: 128, RequireVerifiedEmail: true})
	if err != nil {
		t.Fatal("invalid request commitment fixture", err)
	}
	keys, _ := keyring.New(map[string][]byte{"input": bytes.Repeat([]byte{78}, 32)})
	crypto, _ := envelope.NewService(keys)
	wire, err := owner.retainSignupInput(ctx, crypto, "input", k, profile, b, selected, flow, intent, now)
	if err != nil {
		t.Fatal("original selected creation retention failed", err)
	}
	got, creationAgain, flowAgain, at, err := owner.restoreSignupInput(ctx, crypto, k, profile, wire, intent)
	s, _ := flow.Bindings()
	again, _ := flowAgain.Bindings()
	if err != nil || got != b || !reflect.DeepEqual(creationAgain, selected) || s != again || !at.Equal(now) {
		t.Fatal("original selected creation changed on restoration", err)
	}
	fields, _ := intent.Fields()
	fields[0].Value.Bytes[0] ^= 1
	changed, _ := identity.NewRequestIntent(fields)
	if _, _, _, _, err := owner.restoreSignupInput(ctx, crypto, k, profile, wire, changed); err == nil {
		t.Fatal("different request commitment restored original input")
	}
	// Restore must retain historical input without needing a password or current
	// flow lifetime; it must not silently select a new timestamp/default/account.
	r.Password.Destroy()
	if _, _, _, _, err := owner.restoreSignupInput(ctx, crypto, k, profile, wire, intent); err != nil {
		t.Fatal("password-free original input cannot be recovered")
	}
	// A native password-free recovery request contains neither the password nor
	// the four private intent digests. Recovering authenticated historical input
	// must therefore not require the client to resubmit those digests.
	recoveryOwner, ok := any(&Repository{}).(signupInputRecoveryOwner)
	if !ok {
		t.Fatal("native signup recovery still requires submitted intent")
	}
	recovered, recoveredCreation, recoveredFlow, recoveredAt, err := recoveryOwner.recoverSignupInput(ctx, crypto, k, profile, wire)
	recoveredSpec, _ := recoveredFlow.Bindings()
	if err != nil || recovered != b || !reflect.DeepEqual(recoveredCreation, selected) || recoveredSpec != s || !recoveredAt.Equal(now) {
		t.Fatal("password-free historical recovery changed original input", err)
	}
	if recoveredFlow.Check(now.Add(5*time.Minute), s.Binding, s.Cookie) == nil {
		t.Fatal("original flow expiry renewed by recovery")
	}
	damaged := append([]byte(nil), wire...)
	damaged[len(damaged)-1] ^= 1
	for _, bad := range [][]byte{nil, damaged, bytes.Repeat([]byte{1}, maximumSignupInput+1), append(append([]byte(nil), wire...), 1)} {
		if _, _, _, _, err := recoveryOwner.recoverSignupInput(ctx, crypto, k, profile, bad); err == nil {
			t.Fatal("malformed original input recovered")
		}
	}
	aad, _ := (&Repository{}).signupInputAAD(k, profile)
	for _, plain := range [][]byte{[]byte(`{"Schema":2}`), []byte(`{"Schema":1,"Unknown":true}`), []byte(`{"Schema":1,"Schema":1}`), []byte(`{} {}`)} {
		sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: "input", Context: aad})
		if err != nil {
			t.Fatal(err)
		}
		bad, _ := sealed.MarshalBinary()
		if _, _, _, _, err := recoveryOwner.recoverSignupInput(ctx, crypto, k, profile, bad); err == nil {
			t.Fatal("malformed authenticated input recovered")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, _, _, err := recoveryOwner.recoverSignupInput(canceled, crypto, k, profile, wire); err != context.Canceled {
		t.Fatal("input recovery lost cancellation")
	}
	foreign := k
	foreign.Scope.ActorID = "foreign"
	if _, _, _, _, err := recoveryOwner.recoverSignupInput(ctx, crypto, foreign, profile, wire); err == nil {
		t.Fatal("foreign actor recovered original input")
	}
	for _, mutate := range []func(*identity.CommandBinding, *kernel.PasswordRegistrationIntent, *time.Time){
		func(b *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, _ *time.Time) {
			b.ActorID = "foreign"
		},
		func(b *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, _ *time.Time) {
			b.AnonymousFlowID = "AgICAgICAgICAgICAgICAg"
		},
		func(_ *identity.CommandBinding, s *kernel.PasswordRegistrationIntent, _ *time.Time) {
			s.Creation.Binding.CommandID, _ = identity.NewCommandID()
		},
		func(_ *identity.CommandBinding, s *kernel.PasswordRegistrationIntent, _ *time.Time) {
			s.Creation.Binding.ActorID = "foreign"
		},
		func(_ *identity.CommandBinding, s *kernel.PasswordRegistrationIntent, _ *time.Time) {
			s.Identifier.Verified = true
		},
		func(_ *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, at *time.Time) {
			*at = time.Time{}
		},
		func(_ *identity.CommandBinding, _ *kernel.PasswordRegistrationIntent, at *time.Time) {
			*at = now.Add(5 * time.Minute)
		},
	} {
		bad, modified, at := b, selected, now
		mutate(&bad, &modified, &at)
		if _, err := owner.retainSignupInput(ctx, crypto, "input", k, profile, bad, modified, flow, intent, at); err == nil {
			t.Fatal("inconsistent original prepared input retained")
		}
	}
	// Every legal 256 KiB field payload must fit original preparation custody,
	// including strings that JSON would expand sixfold. Persistence must not
	// introduce a hidden stricter limit or truncate the admitted values.
	large := selected
	large.Creation.Attributes = make([]identity.AttributeUpdate, 64)
	for i := range large.Creation.Attributes {
		large.Creation.Attributes[i] = identity.AttributeUpdate{Name: "field_" + strconv.Itoa(i), Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: strings.Repeat("\x00", 4096)}}}
	}
	if _, err := kernel.PasswordRegistrationFields(large); err != nil {
		t.Fatal("invalid full accepted field-budget fixture", err)
	}
	wire, err = owner.retainSignupInput(ctx, crypto, "input", k, profile, b, large, flow, intent, now)
	if err != nil {
		t.Fatal("legal full-budget field input cannot be retained", err)
	}
	_, largeAgain, _, _, err := owner.restoreSignupInput(ctx, crypto, k, profile, wire, intent)
	if err != nil || !reflect.DeepEqual(largeAgain, large) {
		t.Fatal("full-budget original fields did not round trip")
	}
}
