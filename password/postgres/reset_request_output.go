package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// Explicit projections exist only inside the existing encrypted journal. They
// cannot grant authority; each owner authenticates its original custody and
// final Work separately checks current primary state. No bearer is serialized.
type resetStoredRecipientQuery kernel.RecipientQuery
type resetStoredCredential kernel.CredentialAdmission
type resetStoredRecipient struct {
	Query                                                                        resetStoredRecipientQuery
	Suppressed                                                                   bool
	User                                                                         identity.User
	Identifier                                                                   identity.Identifier
	Verification                                                                 identity.Verification
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
	ObservedAtTime                                                               string
}
type resetStoredRequestIssuance struct {
	Contributor          kernel.ContributorDescriptor
	Grants               []signupStoredGrant
	ResetRecipientUserID identity.UserID
}
type resetStoredRequestOutput struct {
	Schema                     uint8
	Recipient                  resetStoredRecipient
	Credential                 resetStoredCredential
	Enabled                    bool
	Origin                     resetRecipientOrigin
	Global, Tenant             uint64
	Admission                  resetStoredAdmission
	Issuance                   resetStoredRequestIssuance
	IssuanceWire, DeliveryWire []byte
}

func (p *resetRequestPhase) outputAAD(generation uint64) (envelope.Context, error) {
	spec, ok := p.original.Feature()
	if !ok || spec.Operation != resetRequestOperation() || spec.Binding.ValidateFor(spec.Operation) != nil || generation == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Spec       identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{spec, generation, p.runtime.profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-password-reset-request-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *resetRequestPhase) sealOutput(ctx context.Context, generation uint64, s resetRequestSelection, a risk.AuthenticationAdmission, d resetRequestDelivery) ([]byte, error) {
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	r := s.recipient
	stored := resetStoredRequestOutput{Schema: 1, Recipient: resetStoredRecipient{Query: resetStoredRecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion}, Credential: resetStoredCredential(s.credential), Enabled: s.enabled, Origin: resetRecipientOrigin(s.origin), Global: s.global, Tenant: s.tenant, Admission: resetStoredAdmission(a.Prepared()), IssuanceWire: d.issuanceWire, DeliveryWire: d.deliveryWire}
	if !r.ObservedAt.IsZero() {
		stored.Recipient.ObservedAtTime = r.ObservedAt.Format(time.RFC3339Nano)
	}
	if !r.Suppressed {
		plan, e := d.issuance.Plan()
		if e != nil {
			return nil, e
		}
		stored.Issuance.Contributor, stored.Issuance.ResetRecipientUserID = plan.Contributor, plan.ResetRecipientUserID
		stored.Issuance.Grants = make([]signupStoredGrant, len(plan.Grants))
		for i, g := range plan.Grants {
			stored.Issuance.Grants[i] = signupStoredGrant(g)
		}
	}
	plain, err := json.Marshal(stored)
	defer clear(plain)
	if err != nil || len(plain) > maximumResetOutput-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumResetOutput {
		clear(wire)
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

func (p *resetRequestPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) (*resetRequestExecution, error) {
	if ctx == nil || len(wire) == 0 || len(wire) > maximumResetOutput {
		return nil, password.ErrPasswordWork
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumResetOutput-4096 {
		return nil, password.ErrPasswordWork
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var out resetStoredRequestOutput
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, password.ErrPasswordWork
	}
	canonical, err := json.Marshal(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || out.Schema != 1 || out.Global == 0 || out.Tenant == 0 {
		return nil, password.ErrPasswordWork
	}
	defer clear(out.IssuanceWire)
	defer clear(out.DeliveryWire)
	r := out.Recipient
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion}
	if r.ObservedAtTime != "" {
		recipient.ObservedAt, err = time.Parse(time.RFC3339Nano, r.ObservedAtTime)
		if err != nil {
			return nil, password.ErrPasswordWork
		}
	}
	spec, _ := p.original.Feature()
	b := spec.Binding
	if recipient.Validate() != nil || recipient.Query.TenantID != b.TenantID || recipient.Query.UserID != "" || recipient.Query.Kind != identity.IdentifierEmail || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.Query.CanonicalValue != p.canonical {
		return nil, password.ErrPasswordWork
	}
	selection := resetRequestSelection{recipient: recipient, credential: kernel.CredentialAdmission(out.Credential), enabled: out.Enabled, origin: password.ResetGrantSpec(out.Origin), global: out.Global, tenant: out.Tenant}
	prepared := risk.PreparedAuthenticationAdmission(out.Admission)
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	admission, err := p.runtime.custody.Restore(ctx, prepared, scope, p.subject)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	e := &resetRequestExecution{selected: selection, admission: admission, generation: generation, outputDigest: sha256.Sum256(wire)}
	if recipient.Suppressed {
		if selection.credential != (kernel.CredentialAdmission{}) || selection.enabled || selection.origin != (password.ResetGrantSpec{}) || len(out.Issuance.Grants) != 0 || out.Issuance.Contributor != (kernel.ContributorDescriptor{}) || out.Issuance.ResetRecipientUserID != "" || len(out.IssuanceWire) != 0 || len(out.DeliveryWire) != 0 {
			return nil, password.ErrPasswordWork
		}
		return e, nil
	}
	o := selection.origin
	if o.OriginCommandID != b.CommandID || o.TenantID != b.TenantID || o.UserID != recipient.User.ID || o.CredentialID != selection.credential.Credential.ID || o.CredentialVersion != selection.credential.Credential.Version || o.CredentialAuthorityVersion != selection.credential.CredentialAuthorityVersion || o.UserAuthorityVersion != recipient.UserAuthorityVersion || o.IdentifierID != recipient.Identifier.ID || o.IdentifierVersion != recipient.Identifier.Version || o.FactorVersion == 0 || o.CallbackURL != p.request.CallbackURL || selection.credential.Credential.Validate(b.TenantID, o.UserID) != nil || selection.credential.UserAuthorityVersion != recipient.UserAuthorityVersion || selection.credential.IdentifierAuthorityVersion != recipient.IdentifierAuthorityVersion || selection.credential.CredentialAuthorityVersion != recipient.CredentialAuthorityVersion || len(out.Issuance.Grants) != 1 || len(out.IssuanceWire) == 0 || len(out.DeliveryWire) == 0 {
		return nil, password.ErrPasswordWork
	}
	if _, err = p.service.profile.Payload(o); err != nil {
		return nil, password.ErrPasswordWork
	}
	plan := kernel.CapabilityIssuancePlan{Contributor: out.Issuance.Contributor, ResetRecipientUserID: out.Issuance.ResetRecipientUserID, Grants: make([]kernel.CapabilityPlan, len(out.Issuance.Grants))}
	for i, g := range out.Issuance.Grants {
		plan.Grants[i] = kernel.CapabilityPlan(g)
	}
	if plan.ResetRecipientUserID != o.UserID || p.service.issuer.ValidateCapabilityIssuance(b, plan) != nil {
		return nil, password.ErrPasswordWork
	}
	issue, err := p.runtime.delivery.codec.RestorePreparation(ctx, b, generation, plan, out.IssuanceWire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	message, err := p.runtime.delivery.owner.RestorePreparation(ctx, b, generation, out.DeliveryWire)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	actual, err := issue.Plan()
	if err != nil || !reflect.DeepEqual(actual, plan) {
		return nil, password.ErrPasswordWork
	}
	e.artifacts = resetRequestDelivery{issuance: issue, delivery: message}
	return e, nil
}
