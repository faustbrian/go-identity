package postgres

import (
	"bytes"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Bounded contract: the keyed original password command, not later caller
// choices, freezes source, disposition and whole-set cap. Independent reference
// and credential-authority predecessors must agree without renewing provenance.
func passwordSessionCommandFixture(t testing.TB, mode PasswordChangeSessionDisposition, maximum uint32, continued bool) (identity.Command, session.Session, kernel.CredentialReplacementIntent) {
	t.Helper()
	original, _, _ := identifierSessionFixture(t)
	if continued {
		original = continuedRecordFixture(t, true)
	}
	s, _ := original.Bindings()
	a, _ := s.Authority.Bindings()
	intent := kernel.CredentialReplacementIntent{Credential: identity.CredentialRef{ID: identity.CredentialID(s.Authentication.CredentialID), TenantID: s.TenantID, UserID: s.UserID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: original.EffectiveCredentialVersion()}, ExpectedUserVersion: 11, ExpectedAuthorityVersion: a.Credential.Version}
	fields, err := kernel.CredentialReplacementFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := PasswordChangeSessionFields(original, mode, maximum)
	if err != nil {
		t.Fatal(err)
	}
	fields = append(fields, selected...)
	b := revokeBinding()
	b.OperationID, b.SchemaID, b.RecordID = "identity.password.change", "password-change", string(intent.Credential.ID)
	op := passwordChangeOperation()
	command, err := identity.NewFeaturePasswordHashCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, "$argon2id$synthetic-command-custody")
	if err != nil {
		t.Fatal(err)
	}
	return command, original, intent
}

func TestPasswordChangeSessionMappingFreezesCompleteOriginal(t *testing.T) {
	for _, continued := range []bool{false, true} {
		for _, mode := range []PasswordChangeSessionDisposition{PasswordChangePreserveSessions, PasswordChangeRevokeOtherSessions, PasswordChangeRevokeAllSessions} {
			command, original, replacement := passwordSessionCommandFixture(t, mode, 100000, continued)
			plan, err := passwordChangeSessions(command)
			if err != nil || plan.disposition != mode || plan.maximum != 100000 || plan.replacement != replacement {
				t.Fatal("frozen disposition or independent predecessors lost", err)
			}
			want, _, _ := encodeRecord(original)
			got, _, _ := encodeRecord(plan.original)
			if !bytes.Equal(want, got) {
				t.Fatal("complete original changed")
			}
		}
	}
	for _, mode := range []PasswordChangeSessionDisposition{0, 4, 255} {
		source, _, _ := identifierSessionFixture(t)
		if _, err := PasswordChangeSessionFields(source, mode, 1); err == nil {
			t.Fatal("unknown disposition admitted")
		}
	}
	for _, maximum := range []uint32{0, 100001, ^uint32(0)} {
		source, _, _ := identifierSessionFixture(t)
		if _, err := PasswordChangeSessionFields(source, PasswordChangePreserveSessions, maximum); err == nil {
			t.Fatal("unbounded selection admitted")
		}
	}
	if _, err := PasswordChangeSessionFields(session.Session{}, PasswordChangePreserveSessions, 1); err == nil {
		t.Fatal("zero source admitted")
	}
}

func TestPasswordChangeSessionMappingDeniesChangedCommand(t *testing.T) {
	command, _, _ := passwordSessionCommandFixture(t, PasswordChangeRevokeOtherSessions, 17, true)
	projection, _ := command.PasswordHashFeature()
	for _, name := range []string{"password-sessions.disposition", "password-sessions.maximum", "credential.version", "credential.expected-authority-version", "credential.id", "source-session.continuation.command"} {
		for _, mutation := range []string{"absent", "wrong-kind", "changed"} {
			p := projection
			p.Fields = nil
			for _, f := range projection.Fields {
				if f.Name == name {
					if mutation == "absent" {
						continue
					}
					if mutation == "wrong-kind" {
						f.Value = identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}
					} else if f.Value.Kind == identity.FeatureText {
						f.Value.Text = "other"
					} else if name == "password-sessions.maximum" {
						f.Value.Uint64 = 100001
					} else if name == "password-sessions.disposition" {
						f.Value.Uint64 = 4
					} else {
						f.Value.Uint64++
					}
				}
				p.Fields = append(p.Fields, f)
			}
			bad, err := identity.NewFeaturePasswordHashCommand(p, "$argon2id$synthetic-command-custody")
			if err == nil {
				if _, err = passwordChangeSessions(bad); err == nil {
					t.Fatal("changed/partial original admitted", name, mutation)
				}
			}
		}
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(p *identity.FeatureCommandSpec) { p.Binding.ActorID = "other" },
		func(p *identity.FeatureCommandSpec) { p.Binding.RecordID = "other" },
		func(p *identity.FeatureCommandSpec) {
			p.Binding.OperationID = "identity.password.reset"
			p.Operation.OperationID = p.Binding.OperationID
		},
		func(p *identity.FeatureCommandSpec) {
			p.Fields = append(p.Fields, identity.FeatureField{Name: "password-sessions.unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
	} {
		p := projection
		change(&p)
		bad, err := identity.NewFeaturePasswordHashCommand(p, "$argon2id$synthetic-command-custody")
		if err == nil {
			if _, err := passwordChangeSessions(bad); err == nil {
				t.Fatal("foreign command admitted")
			}
		}
	}
}

func TestPasswordChangeSessionSuccessorUsesExactPredecessors(t *testing.T) {
	command, source, _ := passwordSessionCommandFixture(t, PasswordChangePreserveSessions, 17, true)
	plan, err := passwordChangeSessions(command)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := command.PasswordHashFeature()
	successor, err := passwordChangeSessionSuccessor(source, p.Binding, plan.replacement)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := source.Bindings()
	after, _ := successor.Bindings()
	c, ok := successor.CredentialContinuation()
	if !ok || c.CommandID != p.Binding.CommandID || successor.EffectiveCredentialVersion() != 11 || after.Authentication != before.Authentication || after.Version != before.Version || after.LastActivityAt != before.LastActivityAt || after.Lookup != before.Lookup || after.Remember != before.Remember {
		t.Fatal("continued session renewed or lost original evidence")
	}
	wantCSRF, _ := source.CSRFState().Bindings()
	gotCSRF, _ := successor.CSRFState().Bindings()
	if gotCSRF != wantCSRF {
		t.Fatal("synchronizer custody changed")
	}
	for _, mutate := range []func(*kernel.CredentialReplacementIntent){
		func(i *kernel.CredentialReplacementIntent) { i.Credential.Version-- },
		func(i *kernel.CredentialReplacementIntent) { i.ExpectedAuthorityVersion-- },
		func(i *kernel.CredentialReplacementIntent) { i.Credential.ID = "other" },
		func(i *kernel.CredentialReplacementIntent) { i.Credential.TenantID = "other" },
	} {
		i := plan.replacement
		mutate(&i)
		if _, err := passwordChangeSessionSuccessor(source, p.Binding, i); err == nil {
			t.Fatal("stale/foreign continuation admitted")
		}
	}
}

func TestPasswordChangeSessionMappingDeniesUnsupportedProfiles(t *testing.T) {
	source, _, _ := identifierSessionFixture(t)
	for _, mutate := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.Proof.Method = "oauth" },
		func(s *session.SessionSpec) { s.Authentication.Proof.Assurance = authentication.AssuranceMultiFactor },
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.ActiveOrganizationID = "org-a"
			a.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "org-a", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor-a", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
		func(s *session.SessionSpec) {
			a, _ := s.Authority.Bindings()
			a.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey-a", Version: 1}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
		},
	} {
		s, _ := source.Bindings()
		mutate(&s)
		record, err := session.NewSession(s)
		if err != nil {
			t.Fatal("invalid hostile fixture", err)
		}
		if _, err := PasswordChangeSessionFields(record, PasswordChangePreserveSessions, 1); err == nil {
			t.Fatal("unsupported owner profile accepted")
		}
	}
	for _, record := range []session.Session{otpRecordFixture(t, false), otpRecordFixture(t, true)} {
		if _, err := PasswordChangeSessionFields(record, PasswordChangeRevokeAllSessions, 1); err == nil {
			t.Fatal("OTP source accepted by password-only profile")
		}
	}
}

func TestPasswordChangeSessionFieldsOwnProjection(t *testing.T) {
	source := continuedRecordFixture(t, true)
	want, _, _ := encodeRecord(source)
	fields, err := PasswordChangeSessionFields(source, PasswordChangeRevokeOtherSessions, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range fields {
		fields[i].Name = "other"
		if len(fields[i].Value.Bytes) > 0 {
			fields[i].Value.Bytes[0] ^= 1
		}
	}
	got, _, _ := encodeRecord(source)
	if !bytes.Equal(want, got) {
		t.Fatal("projection mutated original")
	}
}

func FuzzPasswordChangeSessionSelection(f *testing.F) {
	f.Add(uint64(1), uint64(1))
	f.Add(uint64(3), uint64(100000))
	f.Add(uint64(257), ^uint64(0))
	f.Fuzz(func(t *testing.T, mode, maximum uint64) {
		command, _, _ := passwordSessionCommandFixture(t, PasswordChangePreserveSessions, 1, true)
		p, _ := command.PasswordHashFeature()
		for i := range p.Fields {
			switch p.Fields[i].Name {
			case "password-sessions.disposition":
				p.Fields[i].Value.Uint64 = mode
			case "password-sessions.maximum":
				p.Fields[i].Value.Uint64 = maximum
			}
		}
		command, err := identity.NewFeaturePasswordHashCommand(p, "$argon2id$synthetic-command-custody")
		if err != nil {
			t.Fatal(err)
		}
		plan, err := passwordChangeSessions(command)
		valid := mode >= 1 && mode <= 3 && maximum >= 1 && maximum <= 100000
		if (err == nil) != valid {
			t.Fatal("selection bounds disagree")
		}
		if err == nil && (uint64(plan.disposition) != mode || uint64(plan.maximum) != maximum) {
			t.Fatal("numeric truncation admitted")
		}
	})
}
