package magiclinkpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Only tokenless original session projections and original risk custody are
// retained in the existing journal. A restart can reconcile/commit this output,
// but cannot reconstruct the ephemeral session bearer or its reveal permission.
type consumeStoredOutput struct {
	Schema    uint8
	Fields    []identity.FeatureField
	Admission storedAdmission
}

func sameFields(a, b []identity.FeatureField) bool { return reflect.DeepEqual(a, b) }

func (p *consumePhase) consumeAAD(generation uint64) (envelope.Context, error) {
	f, ok := p.original.Feature()
	if !ok || f.Operation != consumeOperation() || generation == 0 || p.service == nil {
		return envelope.Context{}, invalid()
	}
	frame, err := json.Marshal(struct {
		Spec       identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{f, generation, p.service.profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, invalid()
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-magic-link-consume-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *consumePhase) sealConsumeOutput(ctx context.Context, generation uint64, fields []identity.FeatureField, a risk.AuthenticationAdmission) ([]byte, error) {
	aad, err := p.consumeAAD(generation)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(consumeStoredOutput{Schema: 1, Fields: fields, Admission: storedAdmission(a.Prepared())})
	defer clear(plain)
	if err != nil || len(plain) > maximumRequestOutput-4096 {
		return nil, invalid()
	}
	sealed, err := p.service.request.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.request.config().ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, invalid()
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > maximumRequestOutput {
		clear(wire)
		return nil, invalid()
	}
	return wire, nil
}

func (p *consumePhase) restoreConsumeOutput(ctx context.Context, generation uint64, wire []byte) (*consumeExecution, identity.Command, error) {
	if p.mfaRequired {
		return p.restoreMFAOutput(ctx, generation, wire)
	}
	deny := func() (*consumeExecution, identity.Command, error) { return nil, identity.Command{}, invalid() }
	if ctx == nil || len(wire) == 0 || len(wire) > maximumRequestOutput {
		return deny()
	}
	aad, err := p.consumeAAD(generation)
	if err != nil {
		return deny()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return deny()
	}
	plain, err := p.service.request.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumRequestOutput-4096 {
		return deny()
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	var stored consumeStoredOutput
	if d.Decode(&stored) != nil || d.Decode(new(any)) != io.EOF || stored.Schema != 1 || len(stored.Fields) == 0 || len(stored.Fields) > 128 {
		return deny()
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return deny()
	}
	for _, field := range stored.Fields {
		if !strings.HasPrefix(field.Name, "session.result.") {
			return deny()
		}
	}
	f, _ := p.original.Feature()
	f.Fields = append(f.Fields, stored.Fields...)
	command, err := identity.NewFeaturePreAuthCommand(f, p.request.Cookie)
	if err != nil {
		return deny()
	}
	record, err := sessionpg.MagicLinkSigninSession(command)
	if err != nil {
		return deny()
	}
	expected, err := sessionpg.MagicLinkSigninSessionFields(record)
	if err != nil || !sameFields(expected, stored.Fields) {
		return deny()
	}
	s, err := record.Bindings()
	meta, metaErr := record.MagicLinkAuthentication().Bindings()
	user, identifier, iv, vv := p.sessionIdentity()
	if err != nil || metaErr != nil || meta.CommandID != f.Binding.CommandID || meta.RequestCommandID != p.origin || meta.CapabilityID != p.proof.CapabilityID || !meta.ValidUntil.Equal(p.proof.ExpiresAt) || s.TenantID != p.request.TenantID || s.UserID != user || meta.IdentifierID != identifier || meta.IdentifierVersion != iv || meta.VerificationVersion != vv || s.IssuedAt.Before(p.grant.Payload().IssuedAt) {
		return deny()
	}
	flow, err := p.flow.Bindings()
	remember, remErr := s.Remember.Bindings()
	originalRemember, originalRemErr := flow.Binding.Intent.Remember.Bindings()
	if err != nil || remErr != nil || originalRemErr != nil || remember != originalRemember {
		return deny()
	}
	vector, err := s.Authority.Bindings()
	if err != nil {
		return deny()
	}
	p.selected.global, p.selected.tenant, p.policyVersion = vector.Global.Version, vector.Tenant.Version, vector.Authorization.Version
	authority, err := p.authority(s.SessionID, s.FamilyID)
	if err != nil {
		return deny()
	}
	authExpected, err := authority.Bindings()
	if err != nil || authExpected != vector {
		return deny()
	}
	scope := risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}
	a, err := p.service.request.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), scope, p.subject)
	if err != nil {
		return deny()
	}
	if p.prepared != (session.PreparedIssuance{}) {
		original, ok := p.prepared.Session()
		if !ok {
			return deny()
		}
		fields, err := sessionpg.MagicLinkSigninSessionFields(original)
		if err != nil || !sameFields(fields, expected) {
			return deny()
		}
	}
	return &consumeExecution{record: record, admission: a, generation: generation, digest: sha256.Sum256(wire)}, command, nil
}
