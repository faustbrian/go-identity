package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// Initialize binds the actual OTP owner's retained digest/lockout metadata.
// Apply selected migrations first. It creates no account, factor, number,
// challenge or session; the primary pool remains caller-owned.
func (s *PhoneVerificationService) Initialize(ctx context.Context) error {
	p := s.state()
	if ctx == nil || p == nil {
		return password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	return p.config().Issuer.Initialize(ctx, p.primary.primary.source.pool)
}

// SendVerification retains one keyed original request, then atomically consumes
// its exact action proof and stores a pending number with its purpose-bound OTP
// and encrypted SMS. Matching replay neither regenerates nor sends another code.
// Committed means queued local intent, not SMS delivery or phone verification.
func (s *PhoneVerificationService) SendVerification(ctx context.Context, r phone.EnrollmentRequest) (out phone.EnrollmentResult, err error) {
	p := s.state()
	if ctx == nil || p == nil {
		return out, password.ErrPasswordWork
	}
	request, err := r.Bindings()
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
	phase, err := p.resolveEnrollment(ctx, request)
	if err != nil {
		return out, err
	}
	plan, err := phase.plan(false)
	if err != nil {
		return out, err
	}
	receipt, err := phase.coordinator.ExecutePreparedFeature(ctx, phase.command, plan)
	if receipt.Binding.CommandID == "" {
		return out, err
	}
	out, mapErr := phone.NewEnrollmentResult(phone.EnrollmentResultSpec{Binding: receipt.Binding, Outcome: receipt.Outcome, IdentifierID: identity.IdentifierID(receipt.Binding.RecordID), Replayed: !phase.applied, RetryAfter: receipt.RetryAfter})
	if mapErr != nil {
		return phone.EnrollmentResult{}, identity.UnavailableError{}
	}
	return out, err
}

func (s *phoneVerificationService) now(ctx context.Context) (time.Time, error) {
	var now time.Time
	if ctx == nil {
		return now, password.ErrPasswordWork
	}
	if err := s.primary.primary.source.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, readerFailure(ctx)
	}
	return now.UTC().Truncate(time.Microsecond), ctx.Err()
}

func (s *phoneVerificationService) resolveEnrollment(ctx context.Context, r phone.EnrollmentRequestSpec) (*phoneEnrollmentPhase, error) {
	intent, err := s.enrollmentRequestIntent(r)
	if err != nil {
		return nil, err
	}
	p := &phoneEnrollmentPhase{service: s, request: r}
	p.coordinator, p.registry, err = s.coordinator(p, nil)
	if err != nil {
		return nil, err
	}
	scope, caller, feature := s.enrollmentRequestScope(r, p.Descriptor())
	binding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return nil, err
	}
	if err = p.restoreRequest(ctx, binding, wire); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *phoneVerificationService) prepareEnrollment(ctx context.Context, r phone.EnrollmentRequestSpec, id identity.CommandID) (*phoneEnrollmentPhase, error) {
	if r.Validate() != nil {
		return nil, phone.ErrInvalidVerification
	}
	record, err := r.Number.Record()
	if err != nil {
		return nil, err
	}
	number, err := s.policy.Restore(ctx, record)
	if err != nil || !number.Equal(r.Number) {
		return nil, phone.ErrNumberInvalid
	}
	candidate, err := phoneEnrollmentIdentifier(id)
	if err != nil {
		return nil, err
	}
	primary, err := s.primary.Prepare(ctx, ActionPrimaryRequest{TenantID: r.TenantID, CommandID: id, RecordID: string(candidate), Session: r.Session, Proof: r.Proof, Caller: r.Caller, CSRFToken: r.CSRFToken})
	if err != nil {
		return nil, err
	}
	original, err := primary.Original()
	if err != nil {
		return nil, err
	}
	b, err := original.Bindings()
	if err != nil || b.UserID != r.UserID {
		return nil, identity.ForbiddenError{}
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: r.TenantID, UserID: r.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return nil, err
	}
	vector, err := b.Authority.Bindings()
	if err != nil || state.AuthorityVersion != vector.Identifier.Version || state.User.Version >= ^uint64(0)-1 || state.AuthorityVersion >= ^uint64(0)-1 {
		return nil, identity.ForbiddenError{}
	}
	factors, err := mfapg.ReadPhoneFactors(ctx, s.primary.primary.source.pool, r.TenantID, r.UserID, min(s.config().MaximumDuration, 5*time.Second))
	if err != nil {
		return nil, err
	}
	intent := kernel.PhoneEnrollmentIntent{Change: identity.IdentifierChange{TenantID: r.TenantID, UserID: r.UserID, ID: candidate, Action: identity.IdentifierAttach, Kind: identity.IdentifierPhone, CanonicalValue: record.E164, DisplayValue: record.Display, NormalizationProfile: record.Profile.ID, NormalizationVersion: record.Profile.Version, ExpectedUserVersion: state.User.Version, ExpectedAuthorityVersion: state.AuthorityVersion}}
	at, err := s.now(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = identity.ApplyIdentifierChange(state, intent.Change, at); err != nil {
		return nil, err
	}
	until, err := primary.Deadline()
	if err != nil {
		return nil, err
	}
	until = until.UTC().Truncate(time.Microsecond)
	fields, err := kernel.PhoneEnrollmentFields(intent)
	if err != nil {
		return nil, err
	}
	fields = append(fields, identity.FeatureField{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: factors.Version()}}, identity.FeatureField{Name: "phone.profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: slices.Clone(s.profile[:])}})
	op := phoneEnrollmentOperation()
	binding := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, UserID: r.UserID, ActorID: identity.ActorID(r.UserID), ActorKind: authorization.SubjectUser, RecordID: string(candidate), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: s.config().PolicyID, PolicyVersion: s.config().RequestKeys.Policy.PolicyVersion, CorrelationID: string(id)}
	command, err := primary.Command(binding, fields)
	if err != nil {
		return nil, err
	}
	input, err := s.config().Issuer.CaptureInput(ctx, binding, intent, original, at, until)
	if err != nil {
		return nil, err
	}
	subject := s.authenticationSubject(r.TenantID, record.E164, r.Network, r.Device)
	return &phoneEnrollmentPhase{service: s, request: r, primary: primary, intent: intent, command: command, subject: subject, factorVersion: factors.Version(), input: input, at: at, until: until}, nil
}

func phoneEnrollmentOperation() identity.FeatureOperation {
	return actionPrimaryOperation("identity.phone.send-verification")
}
func phoneVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.verify", SchemaID: "identity.phone.verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func phoneVerificationDescriptor() kernel.ContributorDescriptor {
	return actionPrimaryDescriptor("identity.phone.send-verification")
}

func phoneCommandProfile(command identity.Command, profile [32]byte, factors uint64) bool {
	s, ok := command.Feature()
	if !ok || factors == 0 {
		return false
	}
	matchedProfile, matchedFactors := false, false
	for _, field := range s.Fields {
		if field.Name == "phone.profile" {
			matchedProfile = field.Value.Kind == identity.FeatureBytes && slices.Equal(field.Value.Bytes, profile[:])
		}
		if field.Name == "phone.factor-version" {
			matchedFactors = field.Value.Kind == identity.FeatureUint64 && field.Value.Uint64 == factors
		}
	}
	return matchedProfile && matchedFactors
}

func (s *phoneVerificationService) authenticationSubject(tenant identity.TenantID, number, network, device string) risk.Subject {
	key := s.config().IdentifierKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-phone-authentication-number-v1\x00" + string(tenant) + "\x00" + number))
	return risk.Subject{Network: network, Device: device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}
}

func (s *phoneVerificationService) prepareRisk(ctx context.Context, b identity.CommandBinding, subject risk.Subject) (risk.AuthenticationAdmission, error) {
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	result, err := s.config().Risk.Evaluation.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: identity.CommandID(b.CorrelationID), Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		return risk.AuthenticationAdmission{}, err
	}
	return s.custody.Prepare(ctx, result, scope, subject)
}

func phoneOutputDigest(wire []byte) [32]byte { return sha256.Sum256(wire) }
