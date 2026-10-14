package reference

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

type passwordOTPCompletionAdmission struct{ phase *passwordOTPCompletionPhase }
type passwordOTPCompletionOutput struct {
	Schema     uint32
	Fields     []identity.FeatureField
	Admission  magicTOTPStoredAdmission
	VerifiedAt time.Time
}

func (p *passwordOTPCompletionPhase) PrepareFeatureAdmission(ctx context.Context, command identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p.source == nil || command != p.mapped {
		return nil, invalidPasswordOTPCompletion()
	}
	if err := p.browser(ctx, time.Now().UTC()); err != nil {
		return nil, err
	}
	selected := p.request.Caller.Clone()
	selected.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(p.source.primary.Recipient.User.ID)}
	selected.Request.Environment.Time = time.Now().UTC()
	decision, err := p.state.sender.config.Coordinator.AdmissionPolicy.Authorization.Decide(ctx, selected)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || decision.Revision != selected.PolicyRevision {
		return nil, identity.ForbiddenError{}
	}
	f, _ := command.Feature()
	scope := risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}
	result, err := p.state.sender.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	p.admission, err = p.state.sender.custody.Prepare(ctx, result, scope)
	if err != nil {
		return nil, err
	}
	a := &passwordOTPCompletionAdmission{p}
	return a, a.Check(ctx)
}
func (a *passwordOTPCompletionAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil {
		return invalidPasswordOTPCompletion()
	}
	now := time.Now().UTC()
	if err := a.phase.browser(ctx, now); err != nil {
		return err
	}
	return a.phase.admission.CheckAt(ctx, now)
}
func (*passwordOTPCompletionPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPasswordOTPCompletion()
}

func (p *passwordOTPCompletionPhase) sessionAuthority(id, family string) (session.AuthoritySnapshot, error) {
	a, err := p.source.primary.Authority.Bindings()
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	keys, err := sessionpg.SessionAuthorityKeys(p.request.TenantID, p.source.primary.Recipient.User.ID, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	factor, err := mfapg.FactorAuthorityKey(p.request.TenantID, p.source.primary.Recipient.User.ID)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	a.SessionFamily = session.AuthorityBinding{ScopeKey: keys.Family, Version: 1}
	a.Session = session.AuthorityBinding{ScopeKey: keys.Session, Version: 1}
	a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: factor, Version: p.source.factor.FactorAuthorityVersion}}
	return session.NewAuthoritySnapshot(a)
}

func (a *passwordOTPCompletionAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	if generation == 0 || p.prepared != (session.PreparedIssuance{}) {
		return nil, invalidPasswordOTPCompletion()
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	family, err := identity.NewSubjectID()
	if err != nil {
		return nil, err
	}
	authority, err := p.sessionAuthority(string(id), string(family))
	if err != nil {
		return nil, err
	}
	c, err := p.source.continuation.Bindings()
	if err != nil {
		return nil, err
	}
	remember, err := c.RememberPolicy.Bindings()
	if err != nil {
		return nil, err
	}
	completion, err := p.completion()
	if err != nil {
		return nil, err
	}
	// This is conservative candidate factor time, not a successful proof. Actual
	// consuming OTP and same-Work completion remain mandatory before any issue.
	now := p.state.config.SessionIssuer.Clock.Now().UTC().Truncate(time.Microsecond)
	metadata, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: p.request.CommandID, PrimaryCommandID: p.source.primary.CommandID, ContinuationID: identity.CommandID(c.ID), ContinuationScopeDigest: completion.ScopeDigest, Method: "otp", FactorID: p.source.factor.FactorID, EnrollmentVersion: p.source.factor.EnrollmentVersion, FactorAuthorityVersion: p.source.factor.FactorAuthorityVersion, ContinuationVersion: c.Version, Remember: remember, VerifiedAt: now, ValidUntil: c.ExpiresAt})
	if err != nil {
		return nil, err
	}
	f, _ := p.original.Feature()
	spec := session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: p.request.TenantID, UserID: p.source.primary.Recipient.User.ID, Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: c.RememberPolicy, Authority: authority, Authentication: p.source.primary.Authentication, IssuedAt: now, LastActivityAt: now}
	p.prepared, err = p.issuer.PrepareMFAPassword(f.Binding, spec, metadata)
	if err != nil {
		return nil, err
	}
	record, ok := p.prepared.Session()
	if !ok {
		return nil, invalidPasswordOTPCompletion()
	}
	fields, err := sessionpg.MFAOTPCompletionSessionFields(record)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(passwordOTPCompletionOutput{Schema: 1, Fields: fields, Admission: magicTOTPStoredAdmission(p.admission.Prepared()), VerifiedAt: now})
	defer clear(plain)
	if err != nil || len(plain) > 57344 {
		return nil, invalidPasswordOTPCompletion()
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	sealed, err := p.state.sender.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.state.sender.config.ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > 65536 {
		return nil, invalidPasswordOTPCompletion()
	}
	return wire, nil
}

func (p *passwordOTPCompletionPhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func() (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, invalidPasswordOTPCompletion()
	}
	if p.source == nil || original != p.mapped || len(wire) == 0 || len(wire) > 65536 {
		return bad()
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return bad()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad()
	}
	plain, err := p.state.sender.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > 57344 {
		return bad()
	}
	var stored passwordOTPCompletionOutput
	if decodePasswordOTPSendJSON(plain, &stored) != nil || stored.Schema != 1 || len(stored.Fields) == 0 || len(stored.Fields) > 128 || stored.VerifiedAt.IsZero() {
		return bad()
	}
	for _, field := range stored.Fields {
		if !strings.HasPrefix(field.Name, "session.result.") {
			return bad()
		}
	}
	f, _ := original.Feature()
	f.Fields = append(f.Fields, stored.Fields...)
	command, err := identity.NewFeatureOneTimeCodePreAuthCommand(f, p.request.Code, p.request.Cookie)
	if err != nil {
		return bad()
	}
	record, err := sessionpg.MFAOTPCompletionSession(command)
	if err != nil {
		return bad()
	}
	fields, err := sessionpg.MFAOTPCompletionSessionFields(record)
	if err != nil || !reflect.DeepEqual(fields, stored.Fields) {
		return bad()
	}
	spec, err := record.Bindings()
	if err != nil || spec.TenantID != p.request.TenantID || spec.UserID != p.source.primary.Recipient.User.ID {
		return bad()
	}
	metadata, err := record.MFAAuthentication().Bindings()
	if err != nil || !metadata.VerifiedAt.Equal(stored.VerifiedAt) || metadata.Method != "otp" || metadata.FactorID != p.source.factor.FactorID || metadata.EnrollmentVersion != p.source.factor.EnrollmentVersion || metadata.PrimaryCommandID != p.source.primary.CommandID {
		return bad()
	}
	wanted, err := p.sessionAuthority(spec.SessionID, spec.FamilyID)
	if err != nil {
		return bad()
	}
	want, _ := wanted.Bindings()
	have, _ := spec.Authority.Bindings()
	if want != have {
		return bad()
	}
	if p.prepared != (session.PreparedIssuance{}) {
		owned, ok := p.prepared.Session()
		if !ok {
			return bad()
		}
		ownedFields, err := sessionpg.MFAOTPCompletionSessionFields(owned)
		if err != nil || !reflect.DeepEqual(ownedFields, fields) {
			return bad()
		}
	}
	scope := risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}
	p.admission, err = p.state.sender.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(stored.Admission), scope)
	if err != nil {
		return bad()
	}
	p.command = command
	plan, err := p.declaration()
	return command, plan, err
}
func (p *passwordOTPCompletionPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	a := &passwordOTPCompletionAdmission{p}
	return a, a.Check(ctx)
}

var _ kernel.FeatureAdmissionPreparationContributor = (*passwordOTPCompletionPhase)(nil)
