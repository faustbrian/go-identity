package magiclinkpostgres

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
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const maximumRequestOutput = 1 << 20

// The journal owns this closed codec marker; it does not select a provider or
// authority profile. Envelope AAD independently authenticates that selection.
const requestOriginPrefix = "MLR2"

// Private projections are confined to the existing authenticated preparation
// journal. They do not replace original issuer, delivery or risk custody.
type storedRecipientQuery kernel.RecipientQuery
type storedGrant kernel.CapabilityPlan
type storedAdmission risk.PreparedAuthenticationAdmission

// This private projection is encrypted only by the existing request journal.
// It strips the public diagnostic/serialization refusal, not any creation field.
type storedProspective kernel.MagicLinkRegistrationIntent
type storedRecipient struct {
	Query                                                                        storedRecipientQuery
	Suppressed                                                                   bool
	User                                                                         identity.User
	Identifier                                                                   identity.Identifier
	Verification                                                                 identity.Verification
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
	Observed                                                                     string
}
type storedIssuance struct {
	Contributor kernel.ContributorDescriptor
	Grants      []storedGrant
	User        identity.UserID
}
type storedOutput struct {
	Schema                     uint8
	Recipient                  storedRecipient
	Global, Tenant, Factor     uint64
	Issued, Expires            time.Time
	Flow                       [32]byte
	Admission                  storedAdmission
	Issuance                   storedIssuance
	IssuanceWire, DeliveryWire []byte
	Prospective                *storedProspective           `json:",omitempty"`
	RequestSpec                *identity.FeatureCommandSpec `json:",omitempty"`
}

func (p *requestPhase) outputAAD(generation uint64, prospective bool) (envelope.Context, error) {
	spec, ok := p.original.Feature()
	if !ok || spec.Operation != requestOperation() || spec.Binding.ValidateFor(spec.Operation) != nil || generation == 0 {
		return envelope.Context{}, invalid()
	}
	if prospective {
		return prospectiveOutputAAD(spec.Binding, generation, p.service.configuration)
	}
	return requestOriginOutputAAD(spec.Binding, generation, p.service.configuration)
}

// Historical signin restoration keeps its exact context. Its complete original
// input is available on retry; it is not reconstructible from a payload digest.
func (p *requestPhase) legacyOutputAAD(generation uint64) (envelope.Context, error) {
	spec, ok := p.original.Feature()
	if !ok || spec.Operation != requestOperation() || spec.Binding.ValidateFor(spec.Operation) != nil || generation == 0 {
		return envelope.Context{}, invalid()
	}
	frame, err := json.Marshal(struct {
		Spec       identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{spec, generation, p.service.configuration})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, invalid()
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-magic-link-request-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *requestPhase) sealOutput(ctx context.Context, generation uint64, s requestSelection, a risk.AuthenticationAdmission, d requestArtifacts) ([]byte, error) {
	aad, err := p.outputAAD(generation, s.prospective != nil)
	if err != nil {
		return nil, err
	}
	flow, err := p.flowDigest()
	if err != nil {
		return nil, err
	}
	r := s.recipient
	stored := storedOutput{Schema: 1, Recipient: storedRecipient{Query: storedRecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion}, Global: s.global, Tenant: s.tenant, Factor: s.factor, Issued: s.issued, Expires: s.expires, Flow: flow, Admission: storedAdmission(a.Prepared()), IssuanceWire: d.issuanceWire, DeliveryWire: d.deliveryWire}
	spec, ok := p.original.Feature()
	if !ok {
		return nil, invalid()
	}
	stored.RequestSpec = &spec
	if s.prospective == nil {
		stored.Schema = 2
	}
	if !r.ObservedAt.IsZero() {
		stored.Recipient.Observed = r.ObservedAt.Format(time.RFC3339Nano)
	}
	if s.prospective != nil {
		creation, err := identity.NewUserCreationCommand(s.prospective.Creation)
		if err != nil {
			return nil, invalid()
		}
		intent := *s.prospective
		intent.Creation, _ = creation.CreateUser()
		projection := storedProspective(intent)
		stored.Prospective = &projection
	}
	if s.delivers() {
		if _, err := p.payload(s); err != nil {
			return nil, err
		}
		plan, e := d.issuance.Plan()
		if e != nil {
			return nil, e
		}
		stored.Issuance.Contributor = plan.Contributor
		stored.Issuance.User = plan.MagicLinkRecipientUserID
		stored.Issuance.Grants = make([]storedGrant, len(plan.Grants))
		for i, g := range plan.Grants {
			stored.Issuance.Grants[i] = storedGrant(g)
		}
	}
	plain, err := json.Marshal(stored)
	defer clear(plain)
	if err != nil || len(plain) > maximumRequestOutput-4096 {
		return nil, invalid()
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, invalid()
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumRequestOutput {
		clear(wire)
		return nil, invalid()
	}
	if stored.Schema == 2 {
		framed := make([]byte, 0, len(requestOriginPrefix)+len(wire))
		framed = append(framed, requestOriginPrefix...)
		framed = append(framed, wire...)
		clear(wire)
		if len(framed) > maximumRequestOutput {
			clear(framed)
			return nil, invalid()
		}
		return framed, nil
	}
	return wire, nil
}

// Restoration is local authentication only. It restores exactly the original
// generation and owner checkpoints, never discovers a recipient, signs a new
// token, renders a template, calls a provider or renews any authority timeline.
func (p *requestPhase) restoreOutput(ctx context.Context, generation uint64, wire []byte) (*requestExecution, error) {
	if ctx == nil || len(wire) == 0 || len(wire) > maximumRequestOutput {
		return nil, invalid()
	}
	originProfile := bytes.HasPrefix(wire, []byte(requestOriginPrefix))
	// The frame selects authenticated storage representation, not submitted
	// intent. SignupIfAllowed may select an existing recipient, whose original
	// login must remain readable for MFA; old unframed signup custody retains
	// its historical prospective context. Original command fields stay exact.
	aad, err := p.outputAAD(generation, !originProfile && p.request.Intent == magiclink.SignupIfAllowed)
	expectedSchema := uint8(1)
	encrypted := wire
	if originProfile {
		expectedSchema = 2
		encrypted = wire[len(requestOriginPrefix):]
	} else if p.request.Intent != magiclink.SignupIfAllowed {
		aad, err = p.legacyOutputAAD(generation)
	}
	if err != nil {
		return nil, err
	}
	sealed, err := envelope.ParseEnvelope(encrypted)
	if err != nil {
		return nil, invalid()
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumRequestOutput-4096 {
		return nil, invalid()
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	var out storedOutput
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return nil, invalid()
	}
	canonical, err := json.Marshal(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) || out.Schema != expectedSchema || out.Global == 0 || out.Tenant == 0 {
		return nil, invalid()
	}
	if originProfile && out.Prospective != nil {
		return nil, invalid()
	}
	if originProfile || p.request.Intent == magiclink.SignupIfAllowed {
		spec, ok := p.original.Feature()
		if !ok || out.RequestSpec == nil || !reflect.DeepEqual(spec, *out.RequestSpec) {
			return nil, invalid()
		}
	} else if out.RequestSpec != nil {
		return nil, invalid()
	}
	defer clear(out.IssuanceWire)
	defer clear(out.DeliveryWire)
	flow, err := p.flowDigest()
	if err != nil || flow != out.Flow {
		return nil, invalid()
	}
	r := out.Recipient
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion}
	if r.Observed != "" {
		recipient.ObservedAt, err = time.Parse(time.RFC3339Nano, r.Observed)
		if err != nil {
			return nil, invalid()
		}
	}
	spec, _ := p.original.Feature()
	b := spec.Binding
	q := kernel.RecipientQuery{TenantID: b.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: p.canonical, Eligibility: kernel.RecipientVerified}
	if recipient.Validate() != nil || recipient.Query != q {
		return nil, invalid()
	}
	selection := requestSelection{recipient: recipient, global: out.Global, tenant: out.Tenant, factor: out.Factor, issued: out.Issued, expires: out.Expires}
	if out.Prospective != nil {
		intent := kernel.MagicLinkRegistrationIntent(*out.Prospective)
		creation, err := identity.NewUserCreationCommand(intent.Creation)
		if err != nil {
			return nil, invalid()
		}
		intent.Creation, _ = creation.CreateUser()
		selection.prospective = &intent
	}
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	a, err := p.service.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(out.Admission), scope, p.subject)
	if err != nil {
		return nil, invalid()
	}
	e := &requestExecution{selected: selection, admission: a, generation: generation, digest: sha256.Sum256(wire)}
	if !selection.delivers() {
		if out.Factor != 0 || !out.Issued.IsZero() || !out.Expires.IsZero() || out.Issuance.Contributor != (kernel.ContributorDescriptor{}) || out.Issuance.User != "" || len(out.Issuance.Grants) != 0 || len(out.IssuanceWire) != 0 || len(out.DeliveryWire) != 0 {
			return nil, invalid()
		}
		return e, nil
	}
	payload, err := p.payload(selection)
	if err != nil {
		return nil, err
	}
	if len(out.Issuance.Grants) != 1 || len(out.IssuanceWire) == 0 || len(out.DeliveryWire) == 0 || string(out.Issuance.User) != payload.Subject {
		return nil, invalid()
	}
	plan := kernel.CapabilityIssuancePlan{Contributor: out.Issuance.Contributor, MagicLinkRecipientUserID: out.Issuance.User, Grants: make([]kernel.CapabilityPlan, len(out.Issuance.Grants))}
	for i, g := range out.Issuance.Grants {
		plan.Grants[i] = kernel.CapabilityPlan(g)
	}
	if p.service.issuer.ValidateCapabilityIssuance(b, plan) != nil {
		return nil, invalid()
	}
	e.issuance, err = p.service.codec.RestorePreparation(ctx, b, generation, plan, out.IssuanceWire)
	if err != nil {
		return nil, invalid()
	}
	e.delivery, err = p.service.config().Delivery.Owner.RestorePreparation(ctx, b, generation, out.DeliveryWire)
	if err != nil {
		return nil, invalid()
	}
	actual, err := e.issuance.Plan()
	if err != nil || !reflect.DeepEqual(actual, plan) {
		return nil, invalid()
	}
	return e, nil
}
