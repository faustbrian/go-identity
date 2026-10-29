package postgres

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// These pure tests prove retained command/result mapping, not current storage
// authority. The genuine PostgreSQL consumer owns creator-removal acceptance.
func organizationVerificationFixture(t *testing.T) (*verificationPhase, apikey.Configuration, apikey.Record) {
	t.Helper()
	c, record := recordFixture(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: record.Owner.Spec().TenantID, Kind: apikey.OwnerOrganization, OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", Version: 7})
	if err != nil {
		t.Fatal(err)
	}
	record.Owner = owner
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{config: func() ServiceConfig {
		return ServiceConfig{Configuration: c, PolicyID: "api-key-policy", PolicyVersion: 9}
	}}
	return &verificationPhase{service: s, candidate: &record, request: apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(id), TenantID: record.Owner.Spec().TenantID, ConfigurationID: c.Spec().ID, ConfigurationRevision: c.Spec().Revision}, presented: apikey.Digest{PepperVersion: 1, Sum: [32]byte{1}}}, c, record
}

func TestOrganizationVerificationRetainsNonHumanOriginalAndRecovery(t *testing.T) {
	p, _, record := organizationVerificationFixture(t)
	command, err := p.originalCommand()
	if err != nil {
		t.Fatal("organization verification cannot construct its actual non-human attempt", err)
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding.UserID != "" || spec.Binding.ActorKind != authorization.SubjectAPIKey || spec.Binding.ActorID != identity.ActorID(record.ID) || spec.Binding.AnonymousFlowID != string(p.request.AttemptID) || spec.Operation.SchemaID != "apikey-verify-organization-v1" {
		t.Fatal("organization attempt borrowed a human or denial-only unknown identity")
	}
	q := p.query()
	if recoveryBinding(q).SchemaID != spec.Binding.SchemaID {
		t.Fatal("original organization attempt cannot reconcile its exact known-key schema")
	}
}

func TestVerificationRetainsUserAndDenialOnlyUnknownVariants(t *testing.T) {
	p, _, _ := organizationVerificationFixture(t)
	_, record := recordFixture(t)
	p.candidate = &record
	command, err := p.originalCommand()
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := command.Feature()
	if spec.Operation != verificationOperation(false) || spec.Binding.UserID != record.Owner.Spec().UserID || spec.Binding.AnonymousFlowID != "" || spec.Binding.ActorID != identity.ActorID(record.ID) || spec.Binding.ActorKind != authorization.SubjectAPIKey {
		t.Fatal("existing human-owned verification was reinterpreted")
	}
	p.candidate = nil
	command, err = p.originalCommand()
	if err != nil {
		t.Fatal(err)
	}
	spec, _ = command.Feature()
	if spec.Operation != verificationOperation(true) || spec.Binding.UserID != "" || spec.Binding.AnonymousFlowID != string(p.request.AttemptID) || spec.Binding.ActorID != identity.ActorID(p.request.ConfigurationID) || spec.Binding.ActorKind != authorization.SubjectServiceAccount || recoveryBinding(p.query()).SchemaID != spec.Binding.SchemaID {
		t.Fatal("unknown denial-only attempt was promoted to a known credential")
	}
}

func TestOrganizationVerificationResultDoesNotBorrowUserAuthority(t *testing.T) {
	_, c, record := organizationVerificationFixture(t)
	wire, err := encodeRecord(record, c)
	if err != nil {
		t.Fatal(err)
	}
	observed := organization.CredentialAuthorityObservation{TenantID: record.Owner.Spec().TenantID, OrganizationID: organization.ID(record.Owner.Spec().OrganizationID), Version: 11, CredentialVersion: record.Owner.Spec().Version, ReadStartedAt: record.CreatedAt, VerifiedAt: record.CreatedAt, ValidUntil: record.CreatedAt.Add(10 * time.Second)}
	e := verificationEffect{Schema: 1, Authenticated: true, Record: wire, Grant: record.Grant, Snapshot: verificationSnapshot{PolicyVersion: 9, ConfigurationVersion: 2, Started: record.CreatedAt, Verified: record.CreatedAt, Until: observed.ValidUntil, Organization: &observed}}
	result, err := e.result(c)
	if err != nil || result.Owner.Spec() != record.Owner.Spec() || result.Owner.Spec().UserID != "" {
		t.Fatal("organization result lost its independent credential owner", err)
	}
	for _, mutate := range []func(*organization.CredentialAuthorityObservation){
		func(o *organization.CredentialAuthorityObservation) { o.CredentialVersion++ },
		func(o *organization.CredentialAuthorityObservation) { o.OrganizationID = "another-organization" },
		func(o *organization.CredentialAuthorityObservation) { o.Actor = organization.Member{UserID: "creator"} },
		func(o *organization.CredentialAuthorityObservation) {
			o.ValidUntil = o.ReadStartedAt.Add(21 * time.Second)
		},
	} {
		bad := observed
		mutate(&bad)
		e.Snapshot.Organization = &bad
		if _, err := e.result(c); err == nil {
			t.Fatal("retained result accepted a foreign epoch, creator or extended observation")
		}
	}
}

func TestOrganizationVerificationSnapshotPreservesOldOmittedOwnerEncoding(t *testing.T) {
	wire, err := json.Marshal(verificationSnapshot{})
	if err != nil || bytes.Contains(wire, []byte("Organization")) {
		t.Fatal("old user and unknown original snapshot encoding changed", err)
	}
}

func TestOrganizationSnapshotRestoresEarlierOriginalClockWithoutRenewal(t *testing.T) {
	p, c, record := organizationVerificationFixture(t)
	config := p.service.config()
	spec := c.Spec()
	spec.ClockUncertainty = 2 * time.Second
	var err error
	config.Configuration, err = apikey.NewConfiguration(spec)
	if err != nil {
		t.Fatal(err)
	}
	config.ActiveEnvelopeKeyID = "snapshot-test"
	p.service.config = func() ServiceConfig { return config }
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	provider, err := keyring.New(map[string][]byte{config.ActiveEnvelopeKeyID: key})
	if err != nil {
		t.Fatal(err)
	}
	p.service.crypto, err = envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	p.original, err = p.originalCommand()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeRecord(record, config.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	// The organization owner's application clock is one second behind the
	// enclosing database clock, within the configured uncertainty budget.
	observed := organization.CredentialAuthorityObservation{TenantID: record.Owner.Spec().TenantID, OrganizationID: organization.ID(record.Owner.Spec().OrganizationID), Version: 11, CredentialVersion: record.Owner.Spec().Version, ReadStartedAt: record.CreatedAt, VerifiedAt: record.CreatedAt.Add(10 * time.Millisecond), ValidUntil: record.CreatedAt.Add(20 * time.Second)}
	x := verificationSnapshot{Schema: 1, Generation: 1, Binding: storedBinding(p.binding), Record: wire, GlobalVersion: 1, TenantVersion: 1, ConfigurationVersion: 1, PolicyVersion: config.PolicyVersion, Permissions: []string{"invoice.read"}, Started: record.CreatedAt.Add(time.Second), Verified: record.CreatedAt.Add(1100 * time.Millisecond), Until: record.CreatedAt.Add(19 * time.Second), Organization: &observed}
	aad, err := p.snapshotContext(1)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := p.service.seal(t.Context(), aad, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.restore(t.Context(), 1, sealed); err != nil {
		t.Fatal("valid original observation rejected solely by cross-clock nesting", err)
	}
	if p.snapshot.Started != x.Started || p.snapshot.Until != x.Until || *p.snapshot.Organization != observed {
		t.Fatal("restoration rewrote original authority time or deadline")
	}
}

func TestOrganizationVerificationPermissionDecisionUsesActualKeyAndOwner(t *testing.T) {
	p, _, record := organizationVerificationFixture(t)
	if _, err := p.originalCommand(); err != nil {
		t.Fatal(err)
	}
	x := verificationSnapshot{PolicyVersion: 9, ConfigurationVersion: 2, Organization: &organization.CredentialAuthorityObservation{Version: 11, CredentialVersion: 7}}
	dc := p.permissionDecision(record, x, "invoice.read")
	if dc.Request.Subject.Kind != authorization.SubjectAPIKey || dc.Request.Subject.ID != authorization.SubjectID(record.ID) || dc.Request.Resource.Type != "organization-api-key" || dc.Request.Resource.ID != authorization.ResourceID(record.Owner.Spec().OrganizationID) || dc.Request.Action != "invoice.read" || dc.PolicyRevision != 9 {
		t.Fatal("permission evaluation used synthetic human or configuration as owner")
	}
	for name, value := range map[authorization.AttributeName]string{"organization.version": "11", "organization.credential-version": "7", "api-key.configuration-id": record.ConfigurationID, "api-key.configuration-revision": "1", "api-key.configuration-authority-version": "2", "api-key.policy-version": "9"} {
		if got, ok := dc.Request.Resource.Attributes[name].String(); !ok || got != value {
			t.Fatal("permission decision dropped current organization or configuration binding", name)
		}
	}
}
