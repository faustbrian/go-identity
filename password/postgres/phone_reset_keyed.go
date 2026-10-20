package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// These explicit private scalars exist only inside authenticated native input
// custody. The public types continue to reject accidental serialization. No raw
// cookie, reference, code, idempotency key or plaintext TOTP secret is retained.
type phoneResetStoredRisk kernel.RiskEvidencePlan
type phoneResetStoredFlow struct {
	ID                               identity.PreAuthTransactionID
	TenantID                         identity.TenantID
	Action, Origin, Callback, Policy string
	Nonce, Identifier                [32]byte
	PolicyVersion, Version           uint64
	IssuedAt, ExpiresAt              time.Time
	Cookie                           session.TokenDigest
}
type phoneResetStoredInput struct {
	Schema                                             uint8
	Spec                                               identity.FeatureCommandSpec
	Risk                                               phoneResetStoredRisk
	Flow                                               phoneResetStoredFlow
	Recipient                                          resetStoredRecipient
	Credential                                         resetStoredCredential
	GlobalVersion, TenantVersion, AuthorizationVersion uint64
	Factor                                             mfapg.TOTPFactorMetadata
	FactorEnvelope                                     []byte
	ObservedAt                                         time.Time
	SMSObservedAt                                      time.Time
	RequestInput                                       []identity.FeatureField
}

type phoneResetKeyPhase struct {
	phoneResetRequestPhase
	service *phoneResetRequestService
	request phone.PasswordResetRequestRequestSpec
}

func (s *phoneResetRequestService) inputAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Namespace != s.c.RequestKeys.Namespace || k.PolicyVersion != s.c.RequestKeys.Policy.PolicyVersion || k.Scope.Method != "POST" || k.Scope.RouteID != phoneResetRequestOperation().OperationID || k.Feature.Contributor != phoneVerificationDescriptor() || k.Feature.Operation != phoneResetRequestOperation() || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, password.ErrPasswordWork
	}
	wire, err := json.Marshal(struct {
		Binding storedRemovalKeyBinding
		Profile [32]byte
	}{storedRemovalKeyBinding(k), s.profile})
	defer clear(wire)
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-password-reset-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

func (p *phoneResetKeyPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	s := p.service
	aad, err := s.inputAAD(k)
	if err != nil {
		return nil, err
	}
	selected, err := s.source.prepare(ctx, p.request)
	if err != nil {
		return nil, err
	}
	original := phoneResetOriginalRisk(p.request, selected)
	admission, err := newPhonePasswordRecoveryRisk(s.primary.pool, s.c.Risk, p.request.Caller, selected.recipient.User.ID)
	if err != nil {
		return nil, err
	}
	// Resolve an already committed original, never evaluate risk or charge
	// counters in request-key preparation. The signed precheck is retained once.
	use, err := admission.issuer.PrepareUse(ctx, original, risk.EvidenceUseRequest{CommandID: string(k.Admission.CommandID), Actor: original.Actor, Recovery: original.Recovery, Reference: p.request.RiskEvidence})
	if err != nil {
		return nil, err
	}
	phase, err := restorePhoneResetRequestPhase(ctx, s.primary.pool, s.primary.c, selected, p.request, admission, original, use, s.c.SMS, s.link, s.crypto, s.c.ActiveEnvelopeKeyID, k.Admission.CommandID, s.c.NumberBindingKeyVersion, nil, kernel.RiskEvidencePlan{})
	if err != nil {
		return nil, err
	}
	st, err := storePhoneResetSelection(phase.source)
	if err != nil {
		return nil, err
	}
	st.Schema = 1
	st.Spec, _ = phase.command.Feature()
	st.Risk = phoneResetStoredRisk(phase.riskPlan)
	st.RequestInput, _ = intent.Fields()
	plain, err := json.Marshal(st)
	defer clear(plain)
	defer clear(st.FactorEnvelope)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := s.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.c.ActiveEnvelopeKeyID, Context: aad})
	if err != nil {
		return nil, readerFailure(ctx)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumKeyedPasswordCustody {
		clear(wire)
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

func storePhoneResetSelection(selected phonePasswordRecoverySelection) (phoneResetStoredInput, error) {
	var st phoneResetStoredInput
	f, err := selected.flow.Bindings()
	if err != nil || f.Binding.Intent.Remember != (session.RememberPolicy{}) {
		return st, password.ErrPasswordWork
	}
	b := f.Binding
	i := b.Intent
	st.Flow = phoneResetStoredFlow{ID: b.ID, TenantID: i.TenantID, Action: i.Action, Origin: i.Origin, Callback: i.CallbackURL, Policy: i.PolicyID, Nonce: i.Nonce, Identifier: i.IdentifierBinding, PolicyVersion: i.PolicyVersion, Version: f.Version, IssuedAt: b.IssuedAt, ExpiresAt: b.ExpiresAt, Cookie: f.Cookie}
	r := selected.recipient
	st.Recipient = resetStoredRecipient{Query: resetStoredRecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAtTime: r.ObservedAt.Format(time.RFC3339Nano)}
	st.Credential = resetStoredCredential(selected.credential)
	st.GlobalVersion, st.TenantVersion, st.AuthorizationVersion = selected.directory.GlobalVersion, selected.directory.TenantVersion, selected.policy.Version
	st.ObservedAt = selected.observedAt
	st.SMSObservedAt = selected.smsObservedAt
	st.Factor, err = selected.factor.Metadata()
	if err != nil {
		return st, err
	}
	sealed, err := selected.factor.Envelope()
	if err != nil {
		return st, err
	}
	st.FactorEnvelope, err = sealed.MarshalBinary()
	return st, err
}

func (s *phoneResetRequestService) openInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, intent identity.RequestIntent) (phoneResetStoredInput, error) {
	st, err := s.openOriginalInput(ctx, k, wire)
	actual, projected := intent.Fields()
	if err != nil || !projected || !reflect.DeepEqual(actual, st.RequestInput) {
		clear(st.FactorEnvelope)
		return phoneResetStoredInput{}, password.ErrPasswordWork
	}
	return st, nil
}

// Original-source reads authenticate the same mapping/envelope but have no
// initiating request body. They must separately authorize the committed command
// and authenticate its original browser before borrowing any restored custody.
func (s *phoneResetRequestService) openOriginalInput(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) (phoneResetStoredInput, error) {
	var st phoneResetStoredInput
	if len(wire) == 0 || len(wire) > maximumKeyedPasswordCustody {
		return st, password.ErrPasswordWork
	}
	aad, err := s.inputAAD(k)
	if err != nil {
		return st, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return st, password.ErrPasswordWork
	}
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody || decodeKeyedPasswordJSON(plain, &st) != nil || st.Schema != 1 {
		return phoneResetStoredInput{}, password.ErrPasswordWork
	}
	b := st.Spec.Binding
	if b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.PolicyVersion != k.PolicyVersion || b.ValidateFor(k.Feature.Operation) != nil || st.Spec.Operation != k.Feature.Operation || st.Flow.TenantID != b.TenantID || st.Flow.Policy != s.primary.c.PolicyID || st.Flow.PolicyVersion != b.PolicyVersion || st.Flow.Action != "identity.phone.password-reset-request" || st.ObservedAt.IsZero() || st.ObservedAt != st.ObservedAt.UTC().Truncate(time.Microsecond) || st.SMSObservedAt.IsZero() || st.SMSObservedAt != st.SMSObservedAt.UTC().Truncate(time.Microsecond) || st.SMSObservedAt.Before(st.ObservedAt) || st.Factor.TenantID != b.TenantID || st.Factor.UserID != b.UserID || st.Recipient.User.ID != b.UserID || st.Credential.Credential.UserID != b.UserID || len(st.FactorEnvelope) == 0 {
		clear(st.FactorEnvelope)
		return phoneResetStoredInput{}, password.ErrPasswordWork
	}
	if len(st.RequestInput) != 2 {
		clear(st.FactorEnvelope)
		return phoneResetStoredInput{}, password.ErrPasswordWork
	}
	for _, field := range st.RequestInput {
		if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 || (field.Name != "profile" && field.Name != "intent") || field.Name == "profile" && !bytes.Equal(field.Value.Bytes, s.profile[:]) {
			clear(st.FactorEnvelope)
			return phoneResetStoredInput{}, password.ErrPasswordWork
		}
	}
	if _, err = identity.NewRequestIntent(st.RequestInput); err != nil {
		clear(st.FactorEnvelope)
		return phoneResetStoredInput{}, password.ErrPasswordWork
	}
	return st, nil
}

func (s *phoneResetRequestService) restoreSelection(ctx context.Context, st phoneResetStoredInput) (phonePasswordRecoverySelection, error) {
	var selected phonePasswordRecoverySelection
	f := st.Flow
	var err error
	selected.flow, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: f.ID, Intent: session.PreAuthIntent{TenantID: f.TenantID, Action: f.Action, Origin: f.Origin, CallbackURL: f.Callback, Nonce: f.Nonce, IdentifierBinding: f.Identifier, PolicyID: f.Policy, PolicyVersion: f.PolicyVersion, Purpose: session.PreAuthPhonePasswordRecovery}, IssuedAt: f.IssuedAt, ExpiresAt: f.ExpiresAt}, Cookie: f.Cookie, Version: f.Version})
	if err != nil {
		return selected, err
	}
	r := st.Recipient
	at, err := time.Parse(time.RFC3339Nano, r.ObservedAtTime)
	if err != nil {
		return selected, password.ErrPasswordWork
	}
	selected.recipient = kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAt: at}
	selected.credential = kernel.CredentialAdmission(st.Credential)
	selected.directory = kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.source.global, TenantID: f.TenantID}, GlobalVersion: st.GlobalVersion, TenantVersion: st.TenantVersion}
	selected.policy = kernel.UserAuthorizationAdmission{Scope: authoritypg.AuthorityScope{TenantID: authorization.TenantID(f.TenantID), SubjectID: authorization.SubjectID(st.Spec.Binding.UserID), PolicyNamespace: s.source.namespace}, Version: st.AuthorizationVersion}
	// Re-read the exact original factor, never reselect an alternative/newer one.
	// These are pending-execution checks; terminal receipt reads happen earlier.
	selected.factor, err = s.source.factors.ReadForPhoneRecovery(ctx, f.TenantID, st.Spec.Binding.UserID, st.Factor.FactorID)
	if err != nil {
		return selected, err
	}
	meta, err := selected.factor.Metadata()
	if err != nil || meta != st.Factor {
		return selected, identity.ForbiddenError{}
	}
	sealed, err := selected.factor.Envelope()
	if err != nil {
		return selected, err
	}
	wire, err := sealed.MarshalBinary()
	defer clear(wire)
	if err != nil || !bytes.Equal(wire, st.FactorEnvelope) {
		return selected, identity.ForbiddenError{}
	}
	selected.observedAt = st.ObservedAt
	selected.smsObservedAt = st.SMSObservedAt
	return selected, nil
}
