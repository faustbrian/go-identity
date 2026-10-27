package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestOrganizationPasswordAdmissionPreservesEveryOtherDimension(t *testing.T) {
	original, _, profile := identifierSessionFixture(t)
	spec, _ := original.Bindings()
	b := revokeBinding()
	b.TenantID, b.UserID, b.ActorID, b.RecordID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID), spec.SessionID
	op := session.OrganizationSelectionOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	c, err := session.NewOrganizationSelectionCommand(b, original, session.ActiveOrganizationSelection{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: "organization", Authority: session.AuthorityBinding{ScopeKey: "organization:selected", Version: 9}})
	if err != nil {
		t.Fatal(err)
	}
	transition, _ := c.Bindings()
	directory, credential, policy, err := OriginalOrganizationPasswordSessionAdmission(profile, transition.Successor, b)
	if err != nil || directory.GlobalVersion != 1 || directory.TenantVersion != 2 || credential.Credential.ID != "password-a" || credential.Credential.Version != 9 || credential.UserAuthorityVersion != 5 || credential.IdentifierAuthorityVersion != 6 || credential.CredentialAuthorityVersion != 7 || policy.Version != 8 {
		t.Fatal("organization profile lost the original password/directory/policy vector", err)
	}
	if _, _, _, err := OriginalSessionAdmission(profile, transition.Successor, b); err == nil {
		t.Fatal("legacy admission silently accepted organization authority")
	}
	cookie, _, _ := csrfAdmissionFixture(t, transition.Successor)
	if _, _, _, err := OriginalOrganizationPasswordSessionAdmission(profile, cookie, b); err == nil {
		t.Fatal("selected cookie provenance entered bearer-only native profile")
	}
	repository := &Repository{issueAdmission: (*IssueAdmissionConfig)(&profile)}
	if _, err := repository.revokeRecordAdmission(transition.Successor, b); err == nil {
		t.Fatal("legacy revocation silently dropped selected organization")
	}
	repository.revokeOrganizationPassword = &OrganizationPasswordSessionAdmission{Profile: profile, Authority: organizationReadAuthority{}}
	if got, err := repository.revokeRecordAdmission(transition.Successor, b); err != nil || !got.organization {
		t.Fatal("selected password logout lost organization fence", err)
	}
	for name, mutate := range map[string]func(*IdentifierAdmissionConfig){
		"audience":   func(c *IdentifierAdmissionConfig) { c.Audience = "other-audience" },
		"namespace":  func(c *IdentifierAdmissionConfig) { c.PolicyNamespace = "other-users" },
		"global":     func(c *IdentifierAdmissionConfig) { c.GlobalAuthorityID = "other-deployment" },
		"method":     func(c *IdentifierAdmissionConfig) { c.AuthenticationMethod = "passkey" },
		"credential": func(c *IdentifierAdmissionConfig) { c.CredentialKind = identity.CredentialPasskey },
		"owner":      func(c *IdentifierAdmissionConfig) { c.CredentialOwner = "another-owner" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			mutate(&candidate)
			if _, _, _, err := OriginalOrganizationPasswordSessionAdmission(candidate, transition.Successor, b); err == nil {
				t.Fatal("organization profile dropped original admission scope")
			}
		})
	}
}

type organizationReadAuthority struct{}

func (organizationReadAuthority) ObserveOrganizationSession(context.Context, session.Session) (OrganizationSessionAuthorityObservation, error) {
	return OrganizationSessionAuthorityObservation{}, session.ErrUnauthenticated
}

func (organizationReadAuthority) RequireOrganizationSession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, session.Session) error {
	return session.ErrUnauthenticated
}

func TestOrganizationSessionAuthorityKeepsOriginalDeadlineAndScope(t *testing.T) {
	source, _, _ := identifierSessionFixture(t)
	spec, _ := source.Bindings()
	vector, _ := spec.Authority.Bindings()
	vector.ActiveOrganizationID = "organization"
	vector.Organization = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "organization:selected", Version: 9}}
	spec.Authority, _ = session.NewAuthoritySnapshot(vector)
	selected, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	now := spec.LastActivityAt.Add(time.Second)
	start := now.Add(-2 * time.Second)
	observation := OrganizationSessionAuthorityObservation{OrganizationID: "organization", Authority: vector.Organization.Binding, ReadStartedAt: now.Add(-5 * time.Second), ValidUntil: now.Add(10 * time.Second)}
	gotStart, gotUntil, err := organizationSessionObservationBounds(selected, observation, start, now)
	if err != nil || gotStart != observation.ReadStartedAt || gotUntil != observation.ValidUntil {
		t.Fatal("organization evidence renewed the earlier owner window", err)
	}
	for name, mutate := range map[string]func(*OrganizationSessionAuthorityObservation){
		"organization": func(o *OrganizationSessionAuthorityObservation) { o.OrganizationID = "another" },
		"key":          func(o *OrganizationSessionAuthorityObservation) { o.Authority.ScopeKey = "another" },
		"zero epoch":   func(o *OrganizationSessionAuthorityObservation) { o.Authority.Version = 0 },
		"zero start":   func(o *OrganizationSessionAuthorityObservation) { o.ReadStartedAt = time.Time{} },
		"future start": func(o *OrganizationSessionAuthorityObservation) { o.ReadStartedAt = now.Add(time.Second) },
		"expired":      func(o *OrganizationSessionAuthorityObservation) { o.ValidUntil = now },
		"renewed": func(o *OrganizationSessionAuthorityObservation) {
			o.ValidUntil = o.ReadStartedAt.Add(20*time.Second + time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := observation
			mutate(&candidate)
			if _, _, err := organizationSessionObservationBounds(selected, candidate, start, now); err == nil {
				t.Fatal("organization evidence crossed original scope or time")
			}
		})
	}
	// A changed epoch is projected as current; the session core compares it to
	// the original vector. It must never be copied back into the stored record.
	observation.Authority.Version++
	if _, _, err := organizationSessionObservationBounds(selected, observation, start, now); err != nil {
		t.Fatal("changed authority cannot reach the core's stale-vector comparison", err)
	}
	if _, _, err := organizationSessionObservationBounds(source, observation, start, now); err == nil {
		t.Fatal("unselected record consumed an organization projection")
	}
}

func TestSelectedOrganizationPasswordProfileRetainsExistingMethods(t *testing.T) {
	_, _, profile := identifierSessionFixture(t)
	base := SelectedSessionAdmissionConfig{SingleFactor: SingleFactorSessionAdmissionConfig{Verified: &profile}}
	_, original, err := selectedSessionAdmission(base)
	if err != nil {
		t.Fatal(err)
	}
	selected := OrganizationPasswordSessionAdmission{Profile: profile, Authority: organizationReadAuthority{}}
	base.OrganizationPassword = &selected
	methods, key, err := selectedSessionAdmission(base)
	if err != nil || len(methods) != 1 || methods[0] != session.AuthenticationVerified || key == original {
		t.Fatal("organization selection did not retain and isolate password admission", err)
	}
	selected.Profile.Audience = "another-audience"
	if _, _, err := selectedSessionAdmission(base); err == nil {
		t.Fatal("organization owner selected a different password audience")
	}
	selected.Profile, selected.Authority = profile, nil
	if _, _, err := selectedSessionAdmission(base); err == nil {
		t.Fatal("missing organization owner silently fell back")
	}
}
