package passwordpostgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type signupCreationOwner interface {
	prepareSignupCreation(context.Context, password.SignupRequest, identity.CommandBinding, identity.UserID, *identity.AttributeProcessor, email.AddressParser, string, uint32, string) (kernel.PasswordRegistrationIntent, error)
}

type signupFieldPolicy struct {
	actor identity.ActorID
	user  identity.UserID
	deny  bool
	calls int
}

func (p *signupFieldPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	p.calls++
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	if identity.ActorID(c.Request.Subject.ID) != p.actor || c.Request.Subject.Kind != authorization.SubjectServiceAccount || c.Request.Tenant != "tenant" || c.Request.Action != "identity.user.create" || c.Request.Resource.Type != "identity.user" || identity.UserID(c.Request.Resource.ID) != p.user {
		return authorization.Decision{}, errors.New("synthetic field scope mismatch")
	}
	outcome := authorization.Allow
	if p.deny {
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
}

// SU02: actual kernel field/default policy and address canonicalization precede
// password work. The new account must not masquerade as the ingress actor.
func TestSignupCreationUsesRealFieldAndAddressOwners(t *testing.T) {
	for _, mode := range []string{"allow", "denied", "self-field", "unknown-field", "invalid-value", "invalid-address", "foreign-actor", "foreign-tenant", "foreign-flow", "foreign-operation", "subject-retarget", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _, _ := nativeSignupFlow(t)
			var keyErr error
			r.IdempotencyKey, keyErr = identity.NewIdempotencyKey(bytes.Repeat([]byte{'J'}, 32))
			if keyErr != nil {
				t.Fatal("invalid initiating-key fixture")
			}
			r.Email = "Person@EXAMPLE.TEST"
			r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
			command, _ := identity.NewCommandID()
			user := identity.UserID("01K70ZJ34CWYGBDM2PWQX65QJ5")
			b := identity.CommandBinding{CommandID: command, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: "identity.password.signup", PolicyID: "signup", PolicyVersion: 3, SchemaID: "password-signup", SchemaVersion: 1, CorrelationID: string(command)}
			policy := &signupFieldPolicy{actor: b.ActorID, user: user, deny: mode == "denied"}
			r.TenantID, b.TenantID, r.Caller.Request.Tenant = "tenant", "tenant", "tenant"
			if r.Validate() != nil || b.ValidateFor(passwordSignupOperation()) != nil {
				t.Fatal("invalid original creation fixture")
			}
			text := func(s string) identity.AttributeValue {
				return identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: s}}
			}
			field := identity.FieldPolicy{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: text("default-name")}
			if mode == "self-field" {
				field.WriteAuthorization = identity.FieldWriteSelf
			}
			schema := identity.AttributeSchema{ID: "signup-fields", Version: 1, Fields: []identity.FieldPolicy{field}}
			processor, err := identity.NewAttributeProcessor(schema, policy, func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
				return s, nil
			}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 3, ValidateCanonicalUserID: func(_ context.Context, actual identity.UserID) error {
				if actual != user {
					return errors.New("synthetic invalid ID")
				}
				return nil
			}, ValidateValue: func(_ context.Context, _ identity.FieldPolicy, v identity.AttributeValue) error {
				if v.Scalar.String == "invalid" {
					return errors.New("synthetic private constraint diagnostic")
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			normalization, _ := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "signup-email", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
			address, err := email.NewAddressParser(email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization, PreserveDisplay: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			switch mode {
			case "unknown-field":
				r.AllowedFields = []identity.AttributeUpdate{{Name: "unknown", Value: text("test")}}
			case "invalid-value":
				r.AllowedFields = []identity.AttributeUpdate{{Name: "name", Value: text("invalid")}}
			case "invalid-address":
				r.Email = "not-an-address"
			case "foreign-actor":
				b.ActorID = "foreign"
			case "foreign-tenant":
				b.TenantID = "foreign"
			case "foreign-flow":
				b.AnonymousFlowID = "AgICAgICAgICAgICAgICAg"
			case "foreign-operation":
				b.OperationID = "identity.password.signin"
			case "subject-retarget":
				b.UserID = user
			case "cancelled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			}
			before := r.Caller.Clone()
			owner, present := any(&Repository{}).(signupCreationOwner)
			if !present {
				t.Fatal("native signup has no owned field/address preparation")
			}
			intent, err := owner.prepareSignupCreation(ctx, r, b, user, processor, address, schema.ID, schema.Version, "email-v1")
			if mode == "allow" {
				// Identifier IDs are tenant-wide, not per-account labels. A literal
				// "email" would collide with every other user's first address.
				if intent.Identifier.ID != identity.IdentifierID(user) {
					t.Fatal("signup identifier did not retain a distinct server-selected identity")
				}
				if err != nil || intent.Creation.Binding.ActorID != b.ActorID || intent.Creation.Binding.UserID != user || intent.Creation.Binding.AnonymousFlowID != "" || intent.Creation.Binding.OperationID != "identity.user.create" || intent.Creation.Binding.SchemaID != schema.ID || intent.Creation.Status != identity.StatusActive || len(intent.Creation.Attributes) != 1 || intent.Creation.Attributes[0].Value.Scalar.String != "default-name" || intent.Identifier.UserID != user || intent.Identifier.CanonicalValue != "Person@example.test" || intent.Identifier.DisplayValue != "Person@EXAMPLE.TEST" || intent.Identifier.Verified || intent.Identifier.Primary || intent.Identifier.Version != 1 || intent.Credential.UserID != user || intent.Credential.Owner != "identity/password" || intent.Credential.Kind != identity.CredentialPassword || intent.Credential.Version != 1 {
					t.Fatal("owned original creation was denied or retargeted", err)
				}
				if _, err := kernel.PasswordRegistrationFields(intent); err != nil {
					t.Fatal("prepared creation cannot bind native registration", err)
				}
				if policy.calls != 2 {
					t.Fatal("whole-set and per-field policy did not both run")
				}
			} else if err == nil || intent.Creation.Binding.CommandID != "" || len(intent.Creation.Attributes) != 0 || intent.Identifier.UserID != "" || intent.Credential.UserID != "" {
				t.Fatal("rejected fields/address retained partial creation")
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("creation lost cancellation")
			}
			if !reflect.DeepEqual(before, r.Caller) || r.Password.Len() == 0 {
				t.Fatal("creation mutated caller provenance or password custody")
			}
		})
	}
}
