package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Trusted projection only: actual native factor verification is separately
// required before a completion effect can persist this record.
func passkeyMFASessionFixture(t *testing.T) (session.Session, identity.CommandBinding, PasskeyAdmissionConfig) {
	t.Helper()
	original, binding, profile := passkeySessionFixture(t)
	s, _ := original.Bindings()
	s.Authentication.Proof.ID = "AAAAAAAAAAAAAAAAAAAAAQ"
	s.Authentication.Proof.Purpose = session.PasskeyMFAPrimaryPurpose
	remember, _ := s.Remember.Bindings()
	m, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{
		CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: "AAAAAAAAAAAAAAAAAAAAAQ",
		ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1},
		Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 3,
		FactorAuthorityVersion: 2, ContinuationVersion: 1, Remember: remember,
		VerifiedAt: s.IssuedAt, ValidUntil: s.Authentication.Proof.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithPasskeyMFA(s, m)
	if err != nil {
		t.Fatal(err)
	}
	return record, binding, profile
}

func TestPasskeyMFASessionAdmissionKeepsIndependentOriginalOwners(t *testing.T) {
	record, binding, profile := passkeyMFASessionFixture(t)
	s, _ := record.Bindings()
	directory, credential, policy, err := passkeyMFASessionAdmission(profile, record, binding)
	if err != nil || directory.GlobalVersion != 1 || directory.TenantVersion != 2 ||
		credential.Credential.Kind != identity.CredentialPasskey || credential.Credential.Owner != "passkey" ||
		credential.Credential.ID != identity.CredentialID(s.Authentication.CredentialID) ||
		credential.Credential.Version != s.Authentication.CredentialVersion || policy.Version != 8 {
		t.Fatal("completed passkey/TOTP lost original native authority", err)
	}
	if _, _, _, err := passkeySessionAdmission(profile, record, binding); err == nil {
		t.Fatal("completed TOTP entered known-empty passkey profile")
	}
	ordinary, _, _ := passkeySessionFixture(t)
	if _, _, _, err := passkeyMFASessionAdmission(profile, ordinary, binding); err == nil {
		t.Fatal("ordinary assertion became second-factor completion")
	}
	for _, mode := range []string{"actor", "tenant", "factor-key"} {
		t.Run(mode, func(t *testing.T) {
			changed, b := s, binding
			v, _ := s.Authority.Bindings()
			switch mode {
			case "actor":
				b.ActorID = "foreign-user"
			case "tenant":
				b.TenantID = "foreign-tenant"
			case "factor-key":
				v.Factor.Binding.ScopeKey = "foreign-factor"
			}
			changed.Authority, err = session.NewAuthoritySnapshot(v)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := session.NewSessionWithPasskeyMFA(changed, record.MFAAuthentication())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := passkeyMFASessionAdmission(profile, candidate, b); err == nil {
				t.Fatal("foreign completed-factor authority admitted")
			}
		})
	}
}

func TestPasskeyMFAMappingEvidenceCannotRenewItsPrimaryLease(t *testing.T) {
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	observation := MFAPasskeySessionAuthorityObservation{
		PasskeyVersion: 3, ReadStartedAt: now.Add(-8 * time.Second), ValidUntil: now.Add(9 * time.Second),
	}
	start, until, err := mfaPasskeyObservationBounds(observation, now.Add(-2*time.Second), now)
	if err != nil || !start.Equal(observation.ReadStartedAt) || !until.Equal(observation.ValidUntil) {
		t.Fatal("MFA passkey mapping evidence renewed original positive lease", err)
	}
	start, until, err = mfaPasskeyObservationBounds(observation, now.Add(-15*time.Second), now)
	if err != nil || !start.Equal(now.Add(-15*time.Second)) || !until.Equal(now.Add(5*time.Second)) {
		t.Fatal("later mapping read renewed earlier primary lookup", err)
	}
	for _, mutate := range []func(*MFAPasskeySessionAuthorityObservation){
		func(o *MFAPasskeySessionAuthorityObservation) { o.PasskeyVersion = 0 },
		func(o *MFAPasskeySessionAuthorityObservation) { o.ReadStartedAt = time.Time{} },
		func(o *MFAPasskeySessionAuthorityObservation) { o.ReadStartedAt = now.Add(time.Second) },
		func(o *MFAPasskeySessionAuthorityObservation) { o.ValidUntil = now },
		func(o *MFAPasskeySessionAuthorityObservation) {
			o.ValidUntil = o.ReadStartedAt.Add(20*time.Second + time.Nanosecond)
		},
	} {
		changed := observation
		mutate(&changed)
		if _, _, err := mfaPasskeyObservationBounds(changed, now, now); err == nil {
			t.Fatal("invalid or expired mapping evidence admitted")
		}
	}
}

type mfaPasskeyTestAuthority struct{}

func (*mfaPasskeyTestAuthority) ObserveMFAPasskeySession(context.Context, string, session.Session) (MFAPasskeySessionAuthorityObservation, error) {
	return MFAPasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
}

func (*mfaPasskeyTestAuthority) RequireMFAPasskeySession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, string, session.Session) error {
	return identity.ForbiddenError{}
}

func TestPasskeyMFASelectedReaderAndRevocationRemainExplicit(t *testing.T) {
	record, binding, profile := passkeyMFASessionFixture(t)
	selected := MFAPasskeySessionAdmission{Profile: profile, Authority: &mfaPasskeyTestAuthority{}}
	methods, only, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{MFAPasskey: &selected})
	if err != nil || len(methods) != 1 || methods[0] != session.AuthenticationVerified {
		t.Fatal("completed passkey/TOTP profile could not be selected", err)
	}
	ordinary := PasskeySessionAdmission{Profile: profile, Authority: &passkeyTestAuthority{}}
	_, weaker, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{Passkey: &ordinary})
	if err != nil || only == weaker {
		t.Fatal("completed-factor cache custody collapsed into known-empty MFA", err)
	}
	_, both, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{Passkey: &ordinary, MFAPasskey: &selected})
	if err != nil || both == only || both == weaker {
		t.Fatal("combined passkey profiles lost distinct cache custody", err)
	}
	for _, mode := range []string{"RP", "audience", "deployment", "policy", "authority", "typed-nil"} {
		bad := selected
		switch mode {
		case "RP":
			bad.Profile.RPNamespace = "rp-b"
		case "audience":
			bad.Profile.Audience = "other"
		case "deployment":
			bad.Profile.GlobalAuthorityID = "other"
		case "policy":
			bad.Profile.PolicyNamespace = "other"
		case "authority":
			bad.Authority = nil
		case "typed-nil":
			bad.Authority = (*mfaPasskeyTestAuthority)(nil)
		}
		if _, _, err := selectedSessionAdmission(SelectedSessionAdmissionConfig{Passkey: &ordinary, MFAPasskey: &bad}); err == nil {
			t.Fatal("conflicting or missing completed-factor owner selected", mode)
		}
	}
	r := &Repository{}
	if _, err := r.revokeRecordAdmission(record, binding); err == nil {
		t.Fatal("completed-factor revocation inferred an owner")
	}
	r.revokePasskey = &passkeySessionSelection{profile: profile, authority: &passkeyTestAuthority{}}
	if _, err := r.revokeRecordAdmission(record, binding); err == nil {
		t.Fatal("known-empty revocation downgraded a completed-factor record")
	}
	r.revokeMFAPasskey = &mfaPasskeySessionSelection{profile: profile, authority: selected.Authority}
	a, err := r.revokeRecordAdmission(record, binding)
	if err != nil || !a.mfaPasskey || a.factor == nil || a.credential == nil || a.factor.EnrollmentVersion != 3 || a.factor.FactorAuthorityVersion != 2 || a.credential.Credential.Kind != identity.CredentialPasskey {
		t.Fatal("revocation dropped original mapping or confirmed enrollment", err)
	}
	if service, err := NewMFAPasskeySessionService(nil, MFAPasskeySessionServiceConfig{}); service != nil || err == nil {
		t.Fatal("missing native session owners admitted")
	}
}

func TestPasskeyMFATOTPCompletionCannotUseProjectedFactorMetadata(t *testing.T) {
	_, _, profile := passkeyMFASessionFixture(t)
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	selected := MFAPasskeySessionAdmission{Profile: profile, Authority: &mfaPasskeyTestAuthority{}}
	effect, err := NewMFAPasskeyTOTPCompletionEffect(config, selected)
	if err != nil || effect == nil {
		t.Fatal("explicit passkey/TOTP completion profile unavailable", err)
	}
	for _, candidate := range []*MFAPasskeyTOTPCompletionEffect{nil, {}, effect} {
		if err := candidate.Check(t.Context(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned Work passed final passkey completion eligibility")
		}
		if _, err := candidate.Apply(t.Context(), kernel.Work{}, nil, identity.Command{}, mfapg.LockedTOTPCompletion{}); err == nil {
			t.Fatal("session issued without recorded same-Work native factor completion")
		}
		if _, err := candidate.Recover(t.Context(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned participant supplied recovery evidence")
		}
	}
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if _, err := effect.Apply(ctx, kernel.Work{}, nil, identity.Command{}, mfapg.LockedTOTPCompletion{}); !errors.Is(err, context.Canceled) {
		t.Fatal("passkey completion effect lost cancellation", err)
	}
	for _, missing := range []MFAPasskeySessionAuthority{nil, (*mfaPasskeyTestAuthority)(nil)} {
		selected.Authority = missing
		if candidate, err := NewMFAPasskeyTOTPCompletionEffect(config, selected); candidate != nil || err == nil {
			t.Fatal("completion guessed absent mapping authority")
		}
	}
}
