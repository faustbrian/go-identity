package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

func phoneChangeSendingOperation() identity.FeatureOperation {
	op := phoneEnrollmentOperation()
	op.SchemaID = "identity.phone.send-verification.change.native-v1"
	return op
}

type phoneChangeSendPhase struct {
	service      *phoneChangeService
	request      phone.ChangeRequestSpec
	primary      ActionPrimaryAdmission
	intent       kernel.PhoneChangeIntent
	previous     kernel.RecipientRecord
	command      identity.Command
	factors      uint64
	subject      risk.Subject
	input        otppg.PhoneChangeSendInput
	prepared     otppg.PreparedPhoneChangeSend
	admission    risk.AuthenticationAdmission
	at, until    time.Time
	generation   uint64
	outputDigest [32]byte
	coordinator  *kernel.Coordinator
	registry     *kernel.ContributorRegistry
}

var _ kernel.FeatureAdmissionPreparationContributor = (*phoneChangeSendPhase)(nil)
var _ kernel.RequestKeyPreparationContributor = (*phoneChangeSendPhase)(nil)

func (*phoneChangeSendPhase) Descriptor() kernel.ContributorDescriptor {
	return phoneVerificationDescriptor()
}
func (*phoneChangeSendPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{phoneChangeSendingOperation()}
}

// SendChange retains a keyed original request, then atomically consumes its
// sending proof and queues one new-number SMS. It neither attaches the new
// number nor retires, unverifies or advances the original phone. A committed
// receipt proves only local OTP/delivery persistence, not SMS delivery or change.
func (s *PhoneChangeService) SendChange(ctx context.Context, request phone.ChangeRequest) (out identity.CommandResult, err error) {
	p := s.state()
	if ctx == nil || p == nil {
		return out, password.ErrPasswordWork
	}
	r, err := request.Bindings()
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	intent, err := p.sendIntent(r)
	if err != nil {
		return out, err
	}
	phase := &phoneChangeSendPhase{service: p, request: r}
	phase.coordinator, phase.registry, err = p.coordinator(phase, nil)
	if err != nil {
		return out, err
	}
	scope, caller, feature := p.sendScope(r, phase.Descriptor())
	b, wire, err := phase.coordinator.ResolvePreparedRequestKey(ctx, scope, r.Enrollment.IdempotencyKey, intent, caller, feature, phase)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	if err = phase.restoreRequest(ctx, b, wire); err != nil {
		return out, err
	}
	plan, err := phase.plan(false)
	if err != nil {
		return out, err
	}
	return phase.coordinator.ExecutePreparedFeature(ctx, phase.command, plan)
}

func (s *phoneChangeService) sendIntent(r phone.ChangeRequestSpec) (identity.RequestIntent, error) {
	if r.Validate() != nil {
		return identity.RequestIntent{}, phone.ErrInvalidChange
	}
	base, err := s.common.enrollmentRequestIntent(r.Enrollment)
	if err != nil {
		return identity.RequestIntent{}, err
	}
	fields, _ := base.Fields()
	previous, err := r.PreviousNumber.Record()
	if err != nil {
		return identity.RequestIntent{}, err
	}
	wire, err := json.Marshal(previous)
	if err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	defer clear(wire)
	key := s.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-phone-change-previous-v1\x00"))
	_, _ = mac.Write(wire)
	fields = append(fields, identity.FeatureField{Name: "previous-number", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: mac.Sum(nil)}},
		identity.FeatureField{Name: "previous-identifier", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.IdentifierID)}},
		identity.FeatureField{Name: "previous-identifier-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedIdentifierVersion}},
		identity.FeatureField{Name: "previous-verification-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.ExpectedVerificationVersion}})
	return identity.NewRequestIntent(fields)
}
func (s *phoneChangeService) sendScope(r phone.ChangeRequestSpec, owner kernel.ContributorDescriptor) (kernel.RequestKeyScope, authorization.DecisionContext, kernel.FeatureRegistration) {
	scope, caller, _ := s.common.enrollmentRequestScope(r.Enrollment, owner)
	return scope, caller, kernel.FeatureRegistration{Contributor: owner, Operation: phoneChangeSendingOperation()}
}

func (s *phoneChangeService) prepareSend(ctx context.Context, r phone.ChangeRequestSpec, id identity.CommandID) (*phoneChangeSendPhase, error) {
	if r.Validate() != nil {
		return nil, phone.ErrInvalidChange
	}
	next, err := r.Enrollment.Number.Record()
	if err != nil {
		return nil, err
	}
	previous, err := r.PreviousNumber.Record()
	if err != nil {
		return nil, err
	}
	for _, record := range []phone.NumberRecord{next, previous} {
		if _, err = s.common.policy.Restore(ctx, record); err != nil {
			return nil, err
		}
	}
	primary, err := s.common.primary.Prepare(ctx, ActionPrimaryRequest{TenantID: r.Enrollment.TenantID, CommandID: id, RecordID: string(id), Session: r.Enrollment.Session, Proof: r.Enrollment.Proof, Caller: r.Enrollment.Caller, CSRFToken: r.Enrollment.CSRFToken})
	if err != nil {
		return nil, err
	}
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	b, err := original.Bindings()
	if err != nil || b.UserID != r.Enrollment.UserID {
		return nil, identity.ForbiddenError{}
	}
	recipient, err := s.common.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: identity.IdentifierPhone, CanonicalValue: previous.E164, NormalizationProfile: previous.Profile.ID, NormalizationVersion: previous.Profile.Version, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return nil, err
	}
	vector, err := b.Authority.Bindings()
	if err != nil || recipient.Suppressed || recipient.Identifier.ID != r.IdentifierID || recipient.Identifier.Version != r.ExpectedIdentifierVersion || recipient.Verification.Version != r.ExpectedVerificationVersion || recipient.IdentifierAuthorityVersion != vector.Identifier.Version {
		return nil, identity.ForbiddenError{}
	}
	factors, err := mfapg.ReadPhoneFactors(ctx, s.common.primary.primary.source.pool, b.TenantID, b.UserID, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	at, err := s.common.now(ctx)
	if err != nil {
		return nil, err
	}
	until, err := primary.Deadline()
	if err != nil {
		return nil, err
	}
	until = until.UTC().Truncate(time.Microsecond)
	intent := kernel.PhoneChangeIntent{Change: identity.IdentifierChange{TenantID: b.TenantID, UserID: b.UserID, ID: r.IdentifierID, Action: identity.IdentifierReplaceVerifiedPhone, Kind: identity.IdentifierPhone, CanonicalValue: next.E164, DisplayValue: next.Display, NormalizationProfile: next.Profile.ID, NormalizationVersion: next.Profile.Version, ExpectedUserVersion: recipient.User.Version, ExpectedAuthorityVersion: recipient.IdentifierAuthorityVersion, ExpectedIdentifierVersion: r.ExpectedIdentifierVersion, ExpectedVerificationVersion: r.ExpectedVerificationVersion}, PreviousNumber: previous.E164, PreviousNormalizationProfile: previous.Profile.ID, PreviousNormalizationVersion: previous.Profile.Version, SendCommandID: id, Reason: string(s.config().Reason)}
	fields, err := kernel.PhoneChangeFields(intent)
	if err != nil {
		return nil, err
	}
	fields = append(fields, identity.FeatureField{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factors.Version()}}, identity.FeatureField{Name: "phone.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}})
	op := phoneChangeSendingOperation()
	binding := identity.CommandBinding{CommandID: id, TenantID: b.TenantID, UserID: b.UserID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, RecordID: string(id), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.config().RequestKeys.Policy.PolicyVersion, CorrelationID: string(id)}
	command, err := primary.Command(binding, fields)
	if err != nil {
		return nil, err
	}
	input, err := s.config().Issuer.CaptureInput(ctx, binding, intent, recipient, original, at, until)
	if err != nil {
		return nil, err
	}
	return &phoneChangeSendPhase{service: s, request: r, primary: primary, intent: intent, previous: recipient, command: command, factors: factors.Version(), subject: s.common.authenticationSubject(b.TenantID, next.E164, r.Enrollment.Network, r.Enrollment.Device), input: input, at: at, until: until}, nil
}

type storedPhoneChangeIntent kernel.PhoneChangeIntent
type phoneChangeStoredSend struct {
	Schema               uint8
	Spec                 identity.FeatureCommandSpec
	Intent               storedPhoneChangeIntent
	Previous             resetStoredRecipient
	NewNumber, OldNumber phone.NumberRecord
	Network, Device      string
	Factors              uint64
	At, Until            time.Time
	RequestInput         []identity.FeatureField
}

func (s *phoneChangeService) sendAAD(k kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if k.Namespace != s.config().RequestKeys.Namespace || k.Scope.Method != "POST" || k.Scope.RouteID != phoneChangeSendingOperation().OperationID || k.Feature.Contributor != phoneVerificationDescriptor() || k.Feature.Operation != phoneChangeSendingOperation() || k.IntentDigest == ([32]byte{}) || k.Admission.FingerprintKeyVersion == 0 || k.PolicyVersion != s.config().RequestKeys.Policy.PolicyVersion {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding storedRemovalKeyBinding
		Profile [32]byte
	}{storedRemovalKeyBinding(k), s.profile})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-change-send-input-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *phoneChangeSendPhase) PrepareRequestKey(ctx context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	aad, err := p.service.sendAAD(k)
	if err != nil {
		return nil, err
	}
	prepared, err := p.service.prepareSend(ctx, p.request, k.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	spec, ok := prepared.command.Feature()
	fields, has := intent.Fields()
	if !ok || !has || spec.Binding.ActorID != k.Scope.ActorID || spec.Binding.TenantID != k.Scope.TenantID || spec.Binding.ActorKind != k.Scope.ActorKind {
		return nil, identity.ForbiddenError{}
	}
	next, err := p.request.Enrollment.Number.Record()
	if err != nil {
		return nil, err
	}
	old, err := p.request.PreviousNumber.Record()
	if err != nil {
		return nil, err
	}
	r := prepared.previous
	stored := phoneChangeStoredSend{Schema: 1, Spec: spec, Intent: storedPhoneChangeIntent(prepared.intent), Previous: resetStoredRecipient{Query: resetStoredRecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAtTime: r.ObservedAt.Format(time.RFC3339Nano)}, NewNumber: next, OldNumber: old, Network: p.request.Enrollment.Network, Device: p.request.Enrollment.Device, Factors: prepared.factors, At: prepared.at, Until: prepared.until, RequestInput: fields}
	plain, err := json.Marshal(stored)
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	return p.service.common.sealPhone(ctx, plain, aad)
}
func (p *phoneChangeSendPhase) restoreRequest(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte) error {
	return p.restoreStoredRequest(ctx, k, wire, true)
}

// Consuming/recovery callers restore authenticated original custody, not a new
// send request. Only the keyed-send replay compares its submitted input again.
func (p *phoneChangeSendPhase) restoreStoredRequest(ctx context.Context, k kernel.RequestKeyPreparationBinding, wire []byte, compareRequest bool) error {
	s := p.service
	aad, err := s.sendAAD(k)
	if err != nil {
		return err
	}
	plain, err := s.common.openPhone(ctx, wire, aad)
	if err != nil {
		return err
	}
	defer clear(plain)
	var stored phoneChangeStoredSend
	if decodeKeyedPasswordJSON(plain, &stored) != nil || stored.Schema != 1 || stored.Factors == 0 || stored.At != stored.At.UTC().Truncate(time.Microsecond) || stored.Until != stored.Until.UTC().Truncate(time.Microsecond) || !stored.Until.After(stored.At) {
		return password.ErrPasswordWork
	}
	b := stored.Spec.Binding
	if b.CommandID != k.Admission.CommandID || b.TenantID != k.Scope.TenantID || b.ActorID != k.Scope.ActorID || b.ActorKind != k.Scope.ActorKind || b.UserID != p.request.Enrollment.UserID || b.RecordID != string(b.CommandID) || b.ValidateFor(k.Feature.Operation) != nil || stored.Spec.Operation != k.Feature.Operation || b.PolicyID != s.config().PolicyID || b.PolicyVersion != s.config().RequestKeys.Policy.PolicyVersion {
		return password.ErrPasswordWork
	}
	expected, err := identity.NewRequestIntent(stored.RequestInput)
	if err != nil {
		return password.ErrPasswordWork
	}
	if compareRequest {
		current, err := s.sendIntent(p.request)
		if err != nil {
			return err
		}
		actual, _ := current.Fields()
		old, _ := expected.Fields()
		a, err := json.Marshal(actual)
		defer clear(a)
		z, e := json.Marshal(old)
		defer clear(z)
		if err != nil || e != nil || !bytes.Equal(a, z) {
			return identity.ForbiddenError{}
		}
	}
	command, err := identity.NewFeatureSessionCommand(stored.Spec, p.request.Enrollment.Session)
	if err != nil {
		return err
	}
	if !phoneCommandProfile(command, s.profile, stored.Factors) {
		return password.ErrPasswordWork
	}
	primary, err := s.common.primary.RestoreCommand(ctx, command, p.request.Enrollment.Caller, p.request.Enrollment.CSRFToken)
	if err != nil {
		return err
	}
	intent := kernel.PhoneChangeIntent(stored.Intent)
	if _, err = kernel.PhoneChangeFields(intent); err != nil || intent.SendCommandID != b.CommandID || intent.Change.TenantID != b.TenantID || intent.Change.UserID != b.UserID || intent.Reason != string(s.config().Reason) {
		return password.ErrPasswordWork
	}
	for _, number := range []phone.NumberRecord{stored.NewNumber, stored.OldNumber} {
		if _, err = s.common.policy.Restore(ctx, number); err != nil {
			return err
		}
	}
	if intent.Change.CanonicalValue != stored.NewNumber.E164 || intent.Change.DisplayValue != stored.NewNumber.Display || intent.Change.NormalizationProfile != stored.NewNumber.Profile.ID || intent.Change.NormalizationVersion != stored.NewNumber.Profile.Version || intent.PreviousNumber != stored.OldNumber.E164 || intent.PreviousNormalizationProfile != stored.OldNumber.Profile.ID || intent.PreviousNormalizationVersion != stored.OldNumber.Profile.Version {
		return password.ErrPasswordWork
	}
	at, err := time.Parse(time.RFC3339Nano, stored.Previous.ObservedAtTime)
	if err != nil {
		return password.ErrPasswordWork
	}
	r := stored.Previous
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAt: at}
	if recipient.Validate() != nil || recipient.Suppressed || recipient.Identifier.ID != intent.Change.ID {
		return password.ErrPasswordWork
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	deadline, err := primary.Deadline()
	if err != nil || stored.Until != deadline.UTC().Truncate(time.Microsecond) {
		return password.ErrPasswordWork
	}
	input, err := s.config().Issuer.CaptureInput(ctx, b, intent, recipient, original, stored.At, stored.Until)
	if err != nil {
		return err
	}
	p.primary, p.intent, p.previous, p.command, p.factors, p.input, p.at, p.until = primary, intent, recipient, command, stored.Factors, input, stored.At, stored.Until
	p.request.Enrollment.Network, p.request.Enrollment.Device = stored.Network, stored.Device
	p.subject = s.common.authenticationSubject(b.TenantID, stored.NewNumber.E164, stored.Network, stored.Device)
	return nil
}

// The original envelope also binds its generation and complete original command;
// caller fields cannot restore a code or redirect a retained new-number SMS.
func (p *phoneChangeSendPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if generation == 0 || sourceBinding(p.command).ValidateFor(phoneChangeSendingOperation()) != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Profile    [32]byte
		Generation uint64
	}{sourceBinding(p.command), p.service.profile, generation})
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-change-send-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// Reuse only the encrypted output shape, not the enrollment command or domain.
type phoneChangeSendAdmission struct {
	phase     *phoneChangeSendPhase
	admission risk.AuthenticationAdmission
}

func (a *phoneChangeSendAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil || ctx == nil || !time.Now().Before(a.phase.until) {
		return identity.ForbiddenError{}
	}
	return a.admission.Check(ctx)
}
func (a *phoneChangeSendAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	output, err := p.service.config().Issuer.Generate(ctx, p.command, p.input, generation)
	if err != nil {
		return nil, err
	}
	defer clear(output)
	plain, err := json.Marshal(phoneEnrollmentOutput{Schema: 1, OTP: output, Admission: phoneAuthenticationAdmission(a.admission.Prepared())})
	defer clear(plain)
	if err != nil || len(plain) > maximumKeyedPasswordCustody-4096 {
		return nil, password.ErrPasswordWork
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	return p.service.common.sealPhone(ctx, plain, aad)
}
func (p *phoneChangeSendPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || !phoneCommandProfile(c, p.service.profile, p.factors) || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != phoneChangeSendingOperation() || plan.SubjectType != "otp_challenge" || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "otp.sent.v1", BeforeVersion: 0, AfterVersion: 1}) || len(plan.Audits) != 1 || !plan.Audits[0].Required || plan.Audits[0].EventType != "identity.identifier.request_verification" || plan.Audits[0].RetentionClass != "standard" || plan.Capability != nil || plan.OTP != nil || plan.CapabilityIssuance != nil || plan.RiskEvidence != nil || plan.CommandCounters != nil {
		return password.ErrPasswordWork
	}
	if p.generation == 0 {
		if plan.Delivery != nil {
			return password.ErrPasswordWork
		}
	} else {
		expected, err := p.prepared.Plan()
		if err != nil || plan.Delivery == nil || plan.Delivery.Contributor != expected.Contributor || !slices.Equal(plan.Delivery.Intents, expected.Intents) {
			return password.ErrPasswordWork
		}
	}
	return nil
}
func (p *phoneChangeSendPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *phoneChangeSendPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return password.ErrPasswordWork
	}
	if err := w.RequireRecipient(ctx, p, p.previous); err != nil {
		return err
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	if _, err := mfapg.RequirePhoneFactors(ctx, w, p, c, p.factors); err != nil {
		return err
	}
	return requireIndependentPhoneRecovery(ctx, w, p.primary, p.intent.Change.TenantID, p.intent.Change.UserID, p.service.signin, p.service.reset)
}
func (p *phoneChangeSendPhase) plan(final bool) (kernel.CommandPlan, error) {
	if p.coordinator == nil || p.registry == nil {
		return kernel.CommandPlan{}, password.ErrPasswordWork
	}
	contributors := p.registry.Descriptors()
	if !final {
		delivery := p.service.config().Issuer.DeliveryContributor().Descriptor()
		contributors = slices.DeleteFunc(contributors, func(d kernel.ContributorDescriptor) bool { return d == delivery })
	}
	plan, err := resetServiceAuditDeclaration(sourceBinding(p.command), phoneChangeSendingOperation(), contributors, "otp_challenge", 0, 1, p.at)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Feature.Contributor = p.Descriptor()
	plan.Lifecycle.EventType = "otp.sent.v1"
	if !final {
		return p.coordinator.PrepareFeaturePreparationPlan(p.command, plan)
	}
	delivery, err := p.prepared.Plan()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan.Delivery = &delivery
	return p.coordinator.PrepareCommandPlan(sourceBinding(p.command), p.command, plan)
}
func (p *phoneChangeSendPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command {
		return nil, password.ErrPasswordWork
	}
	admission, err := p.service.common.prepareRisk(ctx, sourceBinding(c), p.subject)
	if err != nil {
		return nil, err
	}
	a := &phoneChangeSendAdmission{phase: p, admission: admission}
	return a, a.Check(ctx)
}
func (*phoneChangeSendPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, password.ErrPasswordWork
}
func (p *phoneChangeSendPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plain, err := p.service.common.openPhone(ctx, wire, aad)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	defer clear(plain)
	var stored phoneEnrollmentOutput
	if decodeKeyedPasswordJSON(plain, &stored) != nil || stored.Schema != 1 || len(stored.OTP) == 0 || len(stored.OTP) > maximumKeyedPasswordCustody {
		return identity.Command{}, kernel.CommandPlan{}, password.ErrPasswordWork
	}
	defer clear(stored.OTP)
	prepared, err := p.service.config().Issuer.Restore(ctx, c, p.input, generation, stored.OTP)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	b := sourceBinding(c)
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	admission, err := p.service.common.custody.Restore(ctx, risk.PreparedAuthenticationAdmission(stored.Admission), scope, p.subject)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.prepared, p.admission, p.generation, p.outputDigest = prepared, admission, generation, sha256.Sum256(wire)
	plan, err := p.plan(true)
	return c, plan, err
}
func (p *phoneChangeSendPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &phoneChangeSendAdmission{phase: p, admission: p.admission}
	return a, a.Check(ctx)
}
func (p *phoneChangeSendPhase) check(ctx context.Context, w kernel.Work, c identity.Command, final bool) error {
	if c != p.command || p.generation == 0 {
		return password.ErrPasswordWork
	}
	if err := p.primary.Check(ctx, w, p, c); err != nil {
		return err
	}
	// Unlike enrollment, sending changed no epoch: readmit the exact original
	// account/session/credential and old verified recipient without a +1 shim.
	if !final {
		if err := p.primary.Admit(ctx, w, p, c); err != nil {
			return err
		}
	} else {
		original, err := p.primary.Original()
		if err != nil {
			return err
		}
		directory, credential, policy, err := p.service.common.primary.primary.originalAdmission(original, sourceBinding(c))
		if err != nil {
			return err
		}
		if err = w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
			return err
		}
		if _, err = w.RequireActiveCredential(ctx, p, credential); err != nil {
			return err
		}
		if err = w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
			return err
		}
		if err = sessionpg.RequireSession(ctx, w, p.service.common.primary.primary.source.c.Session, original); err != nil {
			return err
		}
		if err = p.service.common.requireCSRF(ctx, w, original, p.primary.primary.custody().request.CSRFToken); err != nil {
			return err
		}
	}
	if err := w.RequireRecipient(ctx, p, p.previous); err != nil {
		return err
	}
	if _, err := mfapg.RequirePhoneFactors(ctx, w, p, c, p.factors); err != nil {
		return err
	}
	if err := requireIndependentPhoneRecovery(ctx, w, p.primary, p.intent.Change.TenantID, p.intent.Change.UserID, p.service.signin, p.service.reset); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.admission.CheckAt(ctx, now)
}
func (p *phoneChangeSendPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if generation != p.generation || digest != p.outputDigest {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err = p.check(ctx, w, c, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.primary.Consume(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err = p.prepared.Persist(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: phoneChangeSendingOperation(), BeforeVersion: 0, AfterVersion: 1}, nil
}
func (p *phoneChangeSendPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return p.check(ctx, w, c, true)
}
func (p *phoneChangeSendPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	a, err := p.service.common.primary.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, err := p.service.config().Issuer.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if a == kernel.RecoveryNotCommitted && b == kernel.RecoveryNotCommitted {
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryUnknown, nil
}
