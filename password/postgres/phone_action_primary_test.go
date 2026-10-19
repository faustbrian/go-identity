package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"slices"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

const phonePrimaryAction = "identity.phone.send-verification"

// This fixture supplies synthetic signed-original storage custody only. It does
// not authenticate a live session or prove admission/consumption in PostgreSQL.
func phonePrimaryFixture(t *testing.T, action string) (*ActionPrimarySource, ActionPrimaryRequest, []identity.FeatureField, identity.CommandBinding) {
	t.Helper()
	now := time.Date(2026, 10, 18, 12, 0, 0, 123456000, time.UTC)
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(key, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	b := func(scope string) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: scope, Version: 1}
	}
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	original, err := session.NewSession(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: "tenant", UserID: "user", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now, LastActivityAt: now, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "bbbbbbbbbbbbbbbbbbbbbb", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.signin", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, ed25519.SeedSize))
	record := auth.SignedReauthenticationRecord{Issuer: "issuer", Environment: "test", KeyID: "evidence", ProofVersion: 1, CredentialID: "password", CredentialVersion: 1, Proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "cccccccccccccccccccccc", Tenant: "tenant", Subject: "user", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "phone-action", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, SessionID: "session", SessionVersion: 1, Action: action}}
	frame, err := record.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	record.Signature = ed25519.Sign(private, frame)
	service := &ReauthenticationService{c: ReauthenticationConfig{Issuer: "issuer", Environment: "test", LookupKeys: []session.DigestKey{key}, VerificationKeys: map[string]ed25519.PublicKey{"evidence": private.Public().(ed25519.PublicKey)}}}
	source := &ActionPrimarySource{primary: &EmailPrimarySource{source: service, action: true, config: EmailPrimaryConfig{Action: action, Audience: "phone-action", MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer, AdministrativeTargets: action == "identity.organization.owner-transfer"}}}
	request := ActionPrimaryRequest{TenantID: "tenant", CommandID: identity.CommandID(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{44}, 16))), RecordID: "phone-record", Session: auth.NewBearerCredential(wire), Proof: record.Proof, Caller: authorization.DecisionContext{Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}}}}
	fields, err := sessionpg.OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeReauthenticationRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := sha256.Sum256(encoded)
	fields = append(fields,
		identity.FeatureField{Name: "password.action-primary.proof.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(proofDigest[:])}},
		identity.FeatureField{Name: "password.action-primary.proof.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(record.Proof.Proof.ID)}},
		identity.FeatureField{Name: "password.action-primary.maximum-age-nanos", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(source.primary.config.MaximumAge)}},
		identity.FeatureField{Name: "password.action-primary.cookie", Value: identity.FeatureValue{Kind: identity.FeatureBool}},
	)
	signedFields, err := actionPrimaryRecordFields(record)
	if err != nil {
		t.Fatal(err)
	}
	fields = append(fields, signedFields...)
	binding := identity.CommandBinding{CommandID: request.CommandID, TenantID: request.TenantID, UserID: "user", ActorID: "user", ActorKind: authorization.SubjectUser, RecordID: request.RecordID, OperationID: action, PolicyID: "phone-action", PolicyVersion: 1, CorrelationID: "phone-request", SchemaID: action + ".native-v1", SchemaVersion: 1}
	if action == "identity.organization.owner-transfer" {
		request.TargetSubjectID, binding.UserID, binding.SchemaID = "target", "target", "organization-membership"
		fields = append(fields, identity.FeatureField{Name: "password.action-primary.target-subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "target"}})
	}
	return source, request, fields, binding
}

func TestPhoneActionPrimaryRestoresExactOriginalCommand(t *testing.T) {
	source, request, fields, binding := phonePrimaryFixture(t, phonePrimaryAction)
	admission, err := source.Restore(context.Background(), request, fields)
	if err != nil {
		t.Fatal("phone original custody rejected", err)
	}
	command, err := admission.Command(binding, []identity.FeatureField{{Name: "phone.canonical", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "+358401234567"}}})
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := command.Feature()
	if !ok || spec.Operation != (identity.FeatureOperation{Owner: "identity/phone", OperationID: phonePrimaryAction, SchemaID: phonePrimaryAction + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) {
		t.Fatal("wrong native phone command")
	}
	restored, err := source.RestoreCommand(context.Background(), command, request.Caller, request.CSRFToken)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := restored.Deadline()
	if err != nil || deadline != request.Proof.Proof.IssuedAt.Add(2*time.Minute) {
		t.Fatal("original freshness changed", err)
	}
	rebuilt, err := restored.Command(binding, []identity.FeatureField{{Name: "phone.canonical", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "+358401234567"}}})
	if err != nil {
		t.Fatal(err)
	}
	rebuiltSpec, _ := rebuilt.Feature()
	if !reflect.DeepEqual(spec, rebuiltSpec) {
		t.Fatal("restart changed original command framing")
	}
	for name, mutate := range map[string]func(*identity.FeatureCommandSpec){
		"operation": func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID, s.Binding.OperationID = "identity.phone.update", "identity.phone.update"
		},
		"schema": func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID, s.Binding.SchemaID = "foreign", "foreign"
		},
		"schema version": func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaVersion, s.Binding.SchemaVersion = 2, 2
		},
		"owner":  func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "foreign" },
		"actor":  func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "foreign" },
		"target": func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			foreign, _ := command.Feature()
			mutate(&foreign)
			c, err := identity.NewFeatureSessionCommand(foreign, request.Session)
			if err != nil {
				t.Fatal("invalid adversarial command fixture", err)
			}
			if _, err := source.RestoreCommand(context.Background(), c, request.Caller, request.CSRFToken); err == nil {
				t.Fatal("foreign command restored original phone custody")
			}
		})
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.ActorID = "foreign" },
		func(b *identity.CommandBinding) { b.UserID = "foreign" },
		func(b *identity.CommandBinding) { b.ActorKind = authorization.SubjectAPIKey },
		func(b *identity.CommandBinding) { b.TenantID = "foreign" },
		func(b *identity.CommandBinding) { b.RecordID = "other-phone" },
		func(b *identity.CommandBinding) { b.CommandID = "dddddddddddddddddddddd" },
		func(b *identity.CommandBinding) { b.OperationID = "identity.phone.update" },
		func(b *identity.CommandBinding) { b.SchemaID = "other-schema" },
		func(b *identity.CommandBinding) { b.SchemaVersion++ },
	} {
		foreign := binding
		mutate(&foreign)
		if _, err := admission.Command(foreign, nil); err == nil {
			t.Fatal("foreign binding retained phone custody")
		}
	}
	if _, err := admission.Command(binding, []identity.FeatureField{fields[0]}); err == nil {
		t.Fatal("additional fields replaced original custody")
	}
}

func TestPhoneActionPrimaryRejectsForeignOrTamperedOriginal(t *testing.T) {
	for name, change := range map[string]func(*ActionPrimarySource, *ActionPrimaryRequest, *[]identity.FeatureField){
		"different target": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.TargetSubjectID = "foreign"
		},
		"explicit self target": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.TargetSubjectID = "user"
		},
		"foreign actor": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.Caller.Request.Subject.ID = "foreign"
		},
		"foreign tenant": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.TenantID = "foreign"
		},
		"foreign audience": func(s *ActionPrimarySource, _ *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			s.primary.config.Audience = "foreign"
		},
		"foreign session": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.Session = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32)))
		},
		"foreign proof action": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.Proof.Action = "identity.phone.update"
		},
		"foreign proof session": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.Proof.SessionID = "foreign"
		},
		"oversized record": func(_ *ActionPrimarySource, r *ActionPrimaryRequest, _ *[]identity.FeatureField) {
			r.RecordID = string(bytes.Repeat([]byte{'x'}, 129))
		},
		"duplicate field": func(_ *ActionPrimarySource, _ *ActionPrimaryRequest, f *[]identity.FeatureField) {
			*f = append(*f, (*f)[0])
		},
		"unknown protected field": func(_ *ActionPrimarySource, _ *ActionPrimaryRequest, f *[]identity.FeatureField) {
			*f = append(*f, identity.FeatureField{Name: "password.action-primary.unrecognized", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
		"tampered digest": func(_ *ActionPrimarySource, _ *ActionPrimaryRequest, f *[]identity.FeatureField) {
			for i := range *f {
				if (*f)[i].Name == "password.action-primary.proof.digest" {
					(*f)[i].Value.Bytes[0] ^= 1
				}
			}
		},
		"tampered signature": func(_ *ActionPrimarySource, _ *ActionPrimaryRequest, f *[]identity.FeatureField) {
			for i := range *f {
				if (*f)[i].Name == actionPrimaryRecordPrefix+"signature" {
					(*f)[i].Value.Bytes[0] ^= 1
				}
			}
		},
		"tampered signed field": func(_ *ActionPrimarySource, _ *ActionPrimaryRequest, f *[]identity.FeatureField) {
			for i := range *f {
				if (*f)[i].Name == actionPrimaryRecordPrefix+"issuer" {
					(*f)[i].Value.Text = "foreign"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, request, fields, _ := phonePrimaryFixture(t, phonePrimaryAction)
			change(source, &request, &fields)
			if _, err := source.Restore(context.Background(), request, fields); err == nil {
				t.Fatal("foreign or tampered phone original accepted")
			}
		})
	}
}

func TestPhoneActionPrimaryKeepsOtherProfilesClosed(t *testing.T) {
	for _, action := range []string{"identity.phone.verify", "identity.phone.signin", "identity.phone.update", "identity.phone.password-signin", "identity.phone.password-reset-request", "identity.phone.password-reset-complete"} {
		source, request, fields, _ := phonePrimaryFixture(t, action)
		if _, err := source.Restore(context.Background(), request, fields); err == nil {
			t.Fatal("unsupported phone action accepted")
		}
	}
	for _, action := range []string{"identity.username.update", "identity.organization.owner-transfer"} {
		source, request, fields, binding := phonePrimaryFixture(t, action)
		admission, err := source.Restore(context.Background(), request, fields)
		if err != nil {
			t.Fatal("existing original profile changed", err)
		}
		command, err := admission.Command(binding, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.RestoreCommand(context.Background(), command, request.Caller, request.CSRFToken); err != nil {
			t.Fatal("existing restart profile changed", err)
		}
	}
}

func TestPhoneRemovalActionPrimaryConservesOriginalScope(t *testing.T) {
	source, request, fields, binding := phonePrimaryFixture(t, "identity.phone.remove")
	admission, err := source.Restore(context.Background(), request, fields)
	if err != nil {
		t.Fatal("signed original phone-removal custody rejected", err)
	}
	command, err := admission.Command(binding, nil)
	if err != nil {
		t.Fatal("phone removal could not construct its own protected command", err)
	}
	if _, err := source.RestoreCommand(context.Background(), command, request.Caller, request.CSRFToken); err != nil {
		t.Fatal("phone removal lost original restart custody", err)
	}
	for name, change := range map[string]func(*ActionPrimaryRequest){
		"target":  func(r *ActionPrimaryRequest) { r.TargetSubjectID = "foreign" },
		"tenant":  func(r *ActionPrimaryRequest) { r.TenantID = "foreign" },
		"session": func(r *ActionPrimaryRequest) { r.Proof.SessionVersion++ },
		"action":  func(r *ActionPrimaryRequest) { r.Proof.Action = phonePrimaryAction },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			change(&candidate)
			if _, err := source.Restore(context.Background(), candidate, fields); err == nil {
				t.Fatal("substituted phone-removal scope accepted")
			}
		})
	}
}
