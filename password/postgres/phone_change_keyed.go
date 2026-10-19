package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// The existing immutable request-key mapping retains the original command and
// OTP attempt together. Only authenticated encrypted fields are stored: no raw
// code, bearer, CSRF synchronizer or caller retry key enters this projection.
type phoneChangeStoredUpdate struct {
	Schema  uint8
	Spec    identity.FeatureCommandSpec
	Counter storedEmailCounter
}

var _ kernel.RequestKeyPreparationContributor = (*phoneChangeUpdatePhase)(nil)

func (s *phoneChangeService) updateIntent(r phone.UpdateRequestSpec) (identity.RequestIntent, error) {
	if r.Validate() != nil {
		return identity.RequestIntent{}, phone.ErrInvalidChange
	}
	key := s.config().IntentKey
	digest := func(purpose string, value []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("identity-phone-change-update-intent-v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(value)
		return mac.Sum(nil)
	}
	proof, err := json.Marshal(r.Proof)
	if err != nil || len(proof) > maximumReauthenticationRecordBytes {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(proof)
	_, sessionID, bearer, err := r.Flow.Bindings()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	codeScope, err := json.Marshal([]string{"identity.phone.update", string(r.TenantID), string(r.UserID), string(r.SendCommandID), sessionID})
	if err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(codeScope)
	code, err := r.Code.KeyedDigest(key, codeScope)
	if err != nil {
		return identity.RequestIntent{}, phone.ErrInvalidChange
	}
	fields := []identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}},
		{Name: "send", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.SendCommandID)}},
		{Name: "subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.UserID)}},
		{Name: "reason", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.Reason)}},
		{Name: "proof", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("proof", proof)}},
		{Name: "bearer", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("bearer", []byte(bearer.Token()))}},
		{Name: "code", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(code[:])}},
	}
	clear(code[:])
	if s.update.primary.config.Transport == session.CredentialCookie {
		csrf, err := r.CSRFToken.Digest(s.common.csrf, session.CSRFBinding{TenantID: r.TenantID, SessionID: "phone-change-update-intent", SessionVersion: 1})
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		binding, err := csrf.Bindings()
		if err != nil {
			return identity.RequestIntent{}, identity.ForbiddenError{}
		}
		fields = append(fields, identity.FeatureField{Name: "csrf", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(binding.Digest[:])}})
	} else if r.CSRFToken != (session.CSRFToken{}) {
		return identity.RequestIntent{}, identity.ForbiddenError{}
	}
	return identity.NewRequestIntent(fields)
}

func (p *phoneChangeUpdatePhase) updateScope() (kernel.RequestKeyScope, authorization.DecisionContext, kernel.FeatureRegistration) {
	r := p.request
	op := p.FeatureOperations()[0]
	scope := kernel.RequestKeyScope{TenantID: r.TenantID, ActorID: identity.ActorID(r.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(p.service.config().RequestKeys.Policy.PolicyVersion)
	caller.Request.Action = authorization.Action(op.OperationID)
	caller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op.OperationID)}
	return scope, caller, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}
}

func (p *phoneChangeUpdatePhase) updateAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if p == nil || p.service == nil || k.Namespace != p.service.config().RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != "identity.phone.update" || k.Feature.Contributor != p.Descriptor() || k.Feature.Operation != p.FeatureOperations()[0] || k.IntentDigest == ([32]byte{}) || k.PolicyVersion != p.service.config().RequestKeys.Policy.PolicyVersion {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding storedRemovalKeyBinding
		Profile [32]byte
	}{storedRemovalKeyBinding(k), p.service.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-change-update-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// PrepareRequestKey creates only an uncommitted candidate outside SQL. The
// coordinator retains exactly one winner before any code comparison/debit.
func (p *phoneChangeUpdatePhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.updateAAD(k)
	if err != nil {
		return nil, err
	}
	expected, err := p.service.updateIntent(p.request)
	actualFields, valid := intent.Fields()
	expectedFields, ok := expected.Fields()
	actual, first := json.Marshal(actualFields)
	defer clear(actual)
	want, second := json.Marshal(expectedFields)
	defer clear(want)
	if err != nil || !valid || !ok || first != nil || second != nil || !bytes.Equal(actual, want) {
		return nil, password.ErrPasswordWork
	}
	candidate := *p
	if err := candidate.prepareLiveUpdate(ctx, k.Admission.CommandID); err != nil {
		return nil, err
	}
	spec, ok := candidate.command.Feature()
	if !ok || spec.Binding.TenantID != k.Scope.TenantID || spec.Binding.ActorID != k.Scope.ActorID || spec.Binding.ActorKind != k.Scope.ActorKind {
		return nil, password.ErrPasswordWork
	}
	plain, err := json.Marshal(phoneChangeStoredUpdate{Schema: 1, Spec: spec, Counter: storedEmailCounter(candidate.counter)})
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	return p.service.common.sealPhone(ctx, plain, aad)
}

func (p *phoneChangeUpdatePhase) restoreUpdate(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	aad, err := p.updateAAD(k)
	if err != nil {
		return err
	}
	plain, err := p.service.common.openPhone(ctx, wire, aad)
	if err != nil {
		return err
	}
	defer clear(plain)
	var stored phoneChangeStoredUpdate
	if decodeKeyedPasswordJSON(plain, &stored) != nil || stored.Schema != 1 {
		return password.ErrPasswordWork
	}
	b := stored.Spec.Binding
	if b.CommandID != k.Admission.CommandID || b.TenantID != p.request.TenantID || b.UserID != p.request.UserID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.RecordID != string(p.intent.Change.ID) || b.ValidateFor(k.Feature.Operation) != nil || stored.Spec.Operation != k.Feature.Operation || b.PolicyID != p.service.config().PolicyID || b.PolicyVersion != p.service.config().RequestKeys.Policy.PolicyVersion {
		return password.ErrPasswordWork
	}
	static := stored.Spec
	static.Fields = slices.DeleteFunc(slices.Clone(stored.Spec.Fields), func(f identity.FeatureField) bool { return len(f.Name) >= 4 && f.Name[:4] == "otp." })
	_, _, bearer, err := p.request.Flow.Bindings()
	if err != nil {
		return err
	}
	root, err := identity.NewFeatureSessionCommand(static, bearer)
	if err != nil {
		return err
	}
	p.primary, err = p.service.update.RestoreCommand(ctx, root, p.request.Caller, p.request.CSRFToken)
	if err != nil {
		return err
	}
	p.command, p.attempt, err = p.confirmation.RestorePrepared(ctx, root, p.request.Code, stored.Spec)
	if err != nil {
		return err
	}
	p.counter = kernel.CommandCounterPlan(stored.Counter)
	return p.service.counters.ValidateCommandCounters(p.command, p.counter)
}

func (p *phoneChangeUpdatePhase) prepareLiveUpdate(ctx context.Context, id identity.CommandID) error {
	b := sourceBinding(p.source.command)
	op := p.FeatureOperations()[0]
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.CommandID, b.RecordID, b.CorrelationID = id, string(p.intent.Change.ID), string(id)
	_, sessionID, bearer, _ := p.request.Flow.Bindings()
	primary, err := p.service.update.Prepare(ctx, ActionPrimaryRequest{TenantID: p.request.TenantID, CommandID: id, RecordID: b.RecordID, Session: bearer, Proof: p.request.Proof, Caller: p.request.Caller, CSRFToken: p.request.CSRFToken})
	if err != nil {
		return err
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	current, err := original.Bindings()
	sent, e := p.source.primary.Original()
	if err != nil || e != nil {
		return identity.ForbiddenError{}
	}
	previous, err := sent.Bindings()
	if err != nil || current.SessionID != sessionID || current.SessionID != previous.SessionID || current.Version != previous.Version || current.UserID != p.request.UserID {
		return identity.ForbiddenError{}
	}
	fields, err := p.confirmation.Fields()
	if err != nil {
		return err
	}
	fields = append(fields, identity.FeatureField{Name: "phone.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(p.service.profile[:])}})
	root, err := primary.Command(b, fields)
	if err != nil {
		return err
	}
	root, counter, err := p.service.counters.PrepareCommandCounters(root, risk.Subject{User: string(b.UserID), Session: sessionID, Network: p.source.request.Enrollment.Network}, p.request.Proof.Proof.IssuedAt.UTC())
	if err != nil {
		return err
	}
	p.primary, p.counter = primary, counter
	p.command, p.attempt, err = p.confirmation.Prepare(ctx, p.service.update.primary.source.pool, root, p.request.Code, p.service.config().CurrentAttemptKeyVersion)
	return err
}
