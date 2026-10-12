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

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// Prospective output remains in the existing original preparation journal.
// Its distinct profile binds immutable original scope; encrypted RequestSpec
// conserves the exact fields needed to authenticate that original intent later.
// Historical signin ciphertext/context is unchanged. Neither scope nor output
// is a reusable creation/possession proof or a new durable authority.
func prospectiveOutputAAD(b identity.CommandBinding, generation uint64, profile [32]byte) (envelope.Context, error) {
	if b.ValidateFor(requestOperation()) != nil || generation == 0 || profile == ([32]byte{}) {
		return envelope.Context{}, invalid()
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Generation uint64
		Profile    [32]byte
	}{b, generation, profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, invalid()
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-magic-link-prospective-request-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// Read only after issuer-owned origin and browser custody are authenticated.
// Require the committed original request and current result-access policy, then
// authenticate its original encrypted creation and every signed caveat. Do not
// restore the historical request's now-expired risk admission as new permission:
// consumption owns a fresh, separately counted admission. No output is exposed,
// regenerated, staged, consumed or given a new expiry here.
func (s *RequestService) readProspectiveOrigin(ctx context.Context, r magiclink.ConsumeRequest, flow session.PreAuthTransaction, grant capability.Grant, origin identity.CommandID) (selection requestSelection, err error) {
	deny := func() (requestSelection, error) { return requestSelection{}, identity.ForbiddenError{} }
	if ctx == nil || ctx.Err() != nil || s == nil || s.config == nil || s.registration == nil || s.config().Possession == nil || s.config().Signup == nil || origin == r.CommandID {
		return deny()
	}
	f, e := flow.Bindings()
	if e != nil || f.Binding.ID != r.PreAuthID || s.admitFlow(magiclink.RequestRequest{TenantID: r.TenantID, PreAuthID: r.PreAuthID, Cookie: r.Cookie, Callback: r.Callback, Origin: r.Origin}, flow, time.Now().UTC()) != nil {
		return deny()
	}
	q := identity.RecoveryQuery{CommandID: origin, TenantID: r.TenantID, AnonymousFlowID: string(r.PreAuthID), ActorID: identity.ActorID(r.Caller.Request.Subject.ID), ActorKind: r.Caller.Request.Subject.Kind, OperationID: requestOperation().OperationID}
	p := &requestPhase{service: s, flow: flow, request: magiclink.RequestRequest{Intent: magiclink.SignupIfAllowed, Callback: r.Callback}}
	coordinator, _, e := s.coordinator(p)
	if e != nil {
		return requestSelection{}, e
	}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(s.config().Coordinator.AdmissionPolicy.PolicyVersion)
	caller.Request.Action = authorization.Action(q.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(r.PreAuthID)}
	observed, e := coordinator.ObserveCommandAdmission(ctx, q, caller)
	if e != nil {
		return requestSelection{}, e
	}
	if observed.Validate() != nil || observed.Absent || observed.Record.Outcome != identity.CommitOutcomeCommitted {
		return deny()
	}
	caller.PolicyRevision = authorization.Revision(s.config().Coordinator.QueryPolicy.PolicyVersion)
	wire, generation, e := coordinator.QueryFeaturePreparation(ctx, q, caller, p.registration(), p)
	defer clear(wire)
	if e != nil {
		return requestSelection{}, e
	}
	aad, e := prospectiveOutputAAD(observed.Record.Binding, generation, s.configuration)
	if e != nil {
		return deny()
	}
	sealed, e := envelope.ParseEnvelope(wire)
	if e != nil {
		return deny()
	}
	plain, e := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if e != nil || len(plain) == 0 || len(plain) > maximumRequestOutput-4096 {
		return deny()
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	var out storedOutput
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return deny()
	}
	defer clear(out.IssuanceWire)
	defer clear(out.DeliveryWire)
	canonical, e := json.Marshal(out)
	defer clear(canonical)
	if e != nil || !bytes.Equal(plain, canonical) || out.Schema != 1 || out.RequestSpec == nil || out.Prospective == nil || out.Factor != 0 || out.Global == 0 || out.Tenant == 0 || !out.Recipient.Suppressed || out.RequestSpec.Binding != observed.Record.Binding || out.RequestSpec.Operation != requestOperation() {
		return deny()
	}
	p.original, e = identity.NewFeatureCommand(*out.RequestSpec)
	if e != nil {
		return deny()
	}
	intent := kernel.MagicLinkRegistrationIntent(*out.Prospective)
	query := kernel.RecipientQuery(out.Recipient.Query)
	p.canonical = query.CanonicalValue
	selection = requestSelection{recipient: kernel.RecipientRecord{Query: query, Suppressed: true}, prospective: &intent, global: out.Global, tenant: out.Tenant, issued: out.Issued, expires: out.Expires}
	actual := grant.Payload()
	expected, e := p.payload(selection)
	if e != nil || actual.ID == "" {
		return deny()
	}
	expected.ID = actual.ID
	if !reflect.DeepEqual(expected, actual) {
		return deny()
	}
	binding, e := p.flowDigest()
	if e != nil || binding != out.Flow {
		return deny()
	}
	spec, e := p.possessionSpec(selection)
	if e != nil || s.config().Possession.Authorize(grant, spec, time.Now().UTC()) != nil {
		return deny()
	}
	return selection, nil
}
