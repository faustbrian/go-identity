package reference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type magicTOTPStoredAdmission risk.PreparedProtectedProviderAdmission
type magicTOTPStoredOutput struct {
	Version   uint8
	Fields    []identity.FeatureField
	Admission magicTOTPStoredAdmission
}
type magicTOTPAdmission struct{ phase *magicTOTPPhase }

func (p *magicTOTPPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.input == nil || c != p.counterCommand {
		return invalidTOTPCompletion()
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (p *magicTOTPPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.input == nil || c != p.counterCommand {
		return invalidTOTPCompletion()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err = p.browser(ctx, c, now); err != nil {
		return err
	}
	primary, err := p.input.primaryCommandID()
	if err != nil {
		return err
	}
	if err = sessionpg.RequireMFAConsumedPreAuth(ctx, w, p, c, p.state.config.Session, p.input.flow, primary); err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, p.directoryAdmission()); err != nil {
		return err
	}
	if err := w.RequireRecipient(ctx, p, p.input.recipient); err != nil {
		return err
	}
	if p.input.passwordPrimary != nil {
		credential, err := p.input.passwordCredential()
		if err != nil {
			return err
		}
		_, err = w.RequireRecipientCredential(ctx, p, p.input.recipient, credential)
		return err
	}
	return nil
}
func (p *magicTOTPPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || p.input == nil || c != p.counterCommand || !p.correct || p.verifiedAt.IsZero() {
		return nil, invalidTOTPCompletion()
	}
	a := &magicTOTPAdmission{p}
	return a, a.Check(ctx)
}
func (a *magicTOTPAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil {
		return invalidTOTPCompletion()
	}
	return a.phase.check(ctx, time.Now().UTC())
}
func (*magicTOTPPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	// Only the explicit original counted/audited admission lane may generate.
	return nil, invalidTOTPCompletion()
}

func (p *magicTOTPPhase) sessionAuthority(id, family string) (session.AuthoritySnapshot, error) {
	q := p.directoryAdmission().Query
	r := p.input.recipient
	keys, err := kernel.KernelAuthorityKeys(q, r.User.ID)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	sessionKeys, err := sessionpg.SessionAuthorityKeys(q.TenantID, r.User.ID, family, id)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	policyKey, err := p.policyScope().Key()
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	factorKey, err := mfapg.FactorAuthorityKey(q.TenantID, r.User.ID)
	if err != nil {
		return session.AuthoritySnapshot{}, err
	}
	bind := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	return session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(keys.Global, p.input.directory.GlobalVersion), Tenant: bind(keys.Tenant, p.input.directory.TenantVersion), User: bind(keys.User, r.UserAuthorityVersion), Identifier: bind(keys.Identifier, r.IdentifierAuthorityVersion), Credential: bind(keys.Credential, r.CredentialAuthorityVersion), SessionFamily: bind(sessionKeys.Family, 1), Session: bind(sessionKeys.Session, 1), Authorization: bind(policyKey, p.input.policy.Version), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind(factorKey, p.input.scope.FactorVersion)}})
}

func (a *magicTOTPAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	if generation == 0 || p.prepared != (session.PreparedIssuance{}) || !p.correct || p.verifiedAt.IsZero() {
		return nil, invalidTOTPCompletion()
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
	scope := p.input.scope
	primary, err := p.input.primaryCommandID()
	if err != nil {
		return nil, err
	}
	remember, err := scope.RememberPolicy.Bindings()
	if err != nil {
		return nil, err
	}
	f, _ := p.input.command.Feature()
	completion, err := p.completion()
	if err != nil {
		return nil, err
	}
	factor := session.MFAAuthenticationSpec{CommandID: f.Binding.CommandID, PrimaryCommandID: primary, ContinuationID: identity.CommandID(scope.ID), ContinuationScopeDigest: completion.ScopeDigest, Method: "totp", FactorAuthorityVersion: scope.FactorVersion, ContinuationVersion: scope.Version, Remember: remember, VerifiedAt: p.verifiedAt, ValidUntil: scope.ExpiresAt}
	if p.recovery {
		set := p.recoverySet
		if set.TenantID != scope.TenantID || set.UserID != identity.UserID(scope.SubjectID) {
			return nil, identity.ForbiddenError{}
		}
		factor.Method, factor.FactorID, factor.EnrollmentVersion = "recovery-code", set.FactorID, set.FactorEnrollmentVersion
		factor.RecoverySetID, factor.RecoverySetVersion = identity.CommandID(set.SetID), set.SetVersion
	} else {
		meta, err := p.input.snapshot.Metadata()
		if err != nil {
			return nil, err
		}
		factor.FactorID, factor.EnrollmentVersion, factor.FactorAuthorityVersion = meta.FactorID, meta.EnrollmentVersion, meta.FactorAuthorityVersion
	}
	mfa, err := session.NewMFAAuthentication(factor)
	if err != nil {
		return nil, err
	}
	spec := session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: f.Binding.TenantID, UserID: p.input.recipient.User.ID, Audience: scope.Audience, Version: 1, FamilyVersion: 1, Remember: scope.RememberPolicy, Authority: authority, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}, IssuedAt: p.verifiedAt, LastActivityAt: p.verifiedAt}
	if p.input.passwordPrimary != nil {
		spec.Authentication = p.input.passwordPrimary.Authentication
		p.prepared, err = p.issuer.PrepareMFAPassword(f.Binding, spec, mfa)
	} else {
		p.prepared, err = p.issuer.PrepareMFAMagicLink(f.Binding, spec, p.input.primary.Authentication, mfa)
	}
	if err != nil {
		return nil, err
	}
	record, ok := p.prepared.Session()
	if !ok {
		return nil, invalidTOTPCompletion()
	}
	fields, err := p.sessionFields(record)
	if err != nil {
		return nil, err
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(magicTOTPStoredOutput{Version: 2, Fields: fields, Admission: magicTOTPStoredAdmission(p.admission.Prepared())})
	defer clear(plain)
	if err != nil || len(plain) > 57344 {
		return nil, invalidTOTPCompletion()
	}
	sealed, err := p.state.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.state.config.ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) == 0 || len(wire) > 65536 {
		clear(wire)
		return nil, invalidTOTPCompletion()
	}
	return wire, nil
}

func (p *magicTOTPPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.input == nil || generation == 0 {
		return envelope.Context{}, invalidTOTPCompletion()
	}
	f, _ := p.input.command.Feature()
	frame, err := json.Marshal(struct {
		Feature    identity.FeatureCommandSpec
		Generation uint64
		Profile    string
	}{f, generation, p.state.config.ConfigurationID})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(frame)
	profile := "identity-mfa-totp-session-output-v1"
	if p.recovery {
		profile = "identity-mfa-recovery-session-output-v1"
	}
	return envelope.NewContext(map[string]string{"profile": profile, "binding": hex.EncodeToString(digest[:])})
}

func (p *magicTOTPPhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	deny := func() (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, invalidTOTPCompletion()
	}
	if p == nil || p.input == nil || original != p.counterCommand || len(wire) == 0 || len(wire) > 65536 {
		return deny()
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return deny()
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return deny()
	}
	plain, err := p.state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > 57344 {
		return deny()
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var stored magicTOTPStoredOutput
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || stored.Version != 2 || len(stored.Fields) == 0 || len(stored.Fields) > 128 {
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
	f, _ := original.Feature()
	f.Fields = append(f.Fields, stored.Fields...)
	var command identity.Command
	if p.recovery {
		if p.input.recovery == nil {
			return deny()
		}
		command, err = identity.NewFeatureRecoveryCodePreAuthCommand(f, p.input.recovery.RecoveryCode, p.input.recovery.Cookie)
	} else {
		command, err = identity.NewFeatureOneTimeCodePreAuthCommand(f, p.input.request.Code, p.input.request.Cookie)
	}
	if err != nil {
		return deny()
	}
	record, err := p.sessionRecord(command)
	if err != nil {
		return deny()
	}
	fields, err := p.sessionFields(record)
	if err != nil || !reflect.DeepEqual(fields, stored.Fields) {
		return deny()
	}
	s, err := record.Bindings()
	if err != nil || s.UserID != p.input.recipient.User.ID || s.TenantID != p.input.scope.TenantID {
		return deny()
	}
	expected, err := p.sessionAuthority(s.SessionID, s.FamilyID)
	actual, authorityErr := s.Authority.Bindings()
	want, expectedErr := expected.Bindings()
	if err != nil || authorityErr != nil || expectedErr != nil || actual != want {
		return deny()
	}
	// Session effects independently authenticate exact primary, factor and
	// continuation metadata under locks; restoration cannot replace those fences.
	if p.prepared != (session.PreparedIssuance{}) {
		owned, ok := p.prepared.Session()
		ownedFields, err := p.sessionFields(owned)
		if !ok || err != nil || !reflect.DeepEqual(ownedFields, fields) {
			return deny()
		}
	}
	scope := risk.Context{Tenant: string(f.Binding.TenantID), Operation: risk.Action(f.Binding.OperationID), Attempt: string(f.Binding.CommandID)}
	admission, err := p.state.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(stored.Admission), scope)
	if err != nil {
		return deny()
	}
	p.admission, p.command = admission, command
	plan, err := p.declaration()
	return command, plan, err
}
func (p *magicTOTPPhase) RestoreFeatureAdmission(ctx context.Context, command identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, command, generation, wire); err != nil {
		return nil, err
	}
	a := &magicTOTPAdmission{p}
	return a, a.Check(ctx)
}

var _ kernel.FeatureAdmissionPreparationContributor = (*magicTOTPPhase)(nil)
