package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// PhoneVerificationIntent identifies the exact initially pending phone and its
// original committed enrollment command. It does not authenticate the caller,
// code or enrollment; the native owner must restore those from retained custody.
// Change is Verify only, with pending identifier/verification predecessors 1/1.
// Number/profile fields compare stored identity; they never re-normalize it.
type PhoneVerificationIntent struct {
	Change               identity.IdentifierChange
	CanonicalNumber      string
	NormalizationProfile string
	NormalizationVersion uint32
	EnrollmentCommandID  identity.CommandID
}

// PhoneVerificationContributor admits original possession/current authority
// before OTP comparison or debit and repeats policy/factor/session checks during
// Apply and final admission. Its pure mapper must return the exact enlisted
// kernel domain. Only the kernel writes identifier verification; only the OTP
// participant reserves and consumes the submitted code in that same Work.
type PhoneVerificationContributor interface {
	FeatureCommitContributor
	FeatureInputAdmissionContributor
	PhoneVerification(identity.Command) (PhoneVerificationIntent, *PhoneEnrollmentDomain, error)
}

func invalidPhoneVerification() error {
	return identity.InvalidInputError{Field: "phone_verification"}
}

func phoneVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.verify",
		SchemaID: "identity.phone.verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// PhoneVerificationFields freezes complete initial confirmation input before
// fingerprinting. No IO, normalization, code comparison or authority admission
// occurs. The returned fields are caller-owned sensitive intent, not proof.
func PhoneVerificationFields(i PhoneVerificationIntent) ([]identity.FeatureField, error) {
	c := i.Change
	if _, err := identity.IdentifierIntentDigest(c); err != nil || c.Action != identity.IdentifierVerify ||
		c.ExpectedIdentifierVersion != 1 || c.ExpectedVerificationVersion != 1 ||
		c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == ^uint64(0) ||
		!phoneEnrollmentNumberShape(i.CanonicalNumber) || i.NormalizationVersion == 0 ||
		len(i.NormalizationProfile) == 0 || len(i.NormalizationProfile) > 128 {
		return nil, invalidPhoneVerification()
	}
	if _, err := identity.ParseCommandID(string(i.EnrollmentCommandID)); err != nil {
		return nil, invalidPhoneVerification()
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "phone-verification." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "phone-verification." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{
		text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)),
		text("canonical-number", i.CanonicalNumber), text("normalization-profile", i.NormalizationProfile),
		number("normalization-version", uint64(i.NormalizationVersion)), number("user-version", c.ExpectedUserVersion),
		number("authority-version", c.ExpectedAuthorityVersion), number("identifier-version", c.ExpectedIdentifierVersion),
		number("verification-version", c.ExpectedVerificationVersion), text("enrollment-command", string(i.EnrollmentCommandID)),
	}, nil
}

func phoneVerificationCommand(p PhoneVerificationContributor, command identity.Command, plan CommandPlan) (PhoneVerificationIntent, *PhoneEnrollmentDomain, error) {
	s, ok := commandFeature(command)
	if !ok || p == nil || s.Operation != phoneVerificationOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation ||
		plan.Feature.Contributor != (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) ||
		plan.SubjectType != "identifier" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.verified.v1" ||
		plan.Lifecycle.BeforeVersion != 1 || plan.Lifecycle.AfterVersion != 2 || plan.Capability != nil || plan.CapabilityIssuance != nil ||
		plan.Delivery != nil || plan.OTP == nil || plan.OTP.Mode != OTPConsume || plan.MFACompletion != nil || plan.MFAContinuation != nil ||
		s.Binding.ActorKind != authorization.SubjectUser || string(s.Binding.ActorID) != string(s.Binding.UserID) || len(plan.Audits) == 0 {
		return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
	}
	if _, present := command.SessionToken(); !present {
		return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
	}
	for _, a := range plan.Audits {
		if !a.Required || a.RetentionClass != "protected" {
			return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
		}
	}
	i, d, err := p.PhoneVerification(command)
	if err != nil || d == nil || d.repository == nil || !d.reuse.valid() ||
		d.profile != i.NormalizationProfile || d.version != i.NormalizationVersion ||
		i.Change.TenantID != s.Binding.TenantID || i.Change.UserID != s.Binding.UserID || string(i.Change.ID) != s.Binding.RecordID ||
		i.EnrollmentCommandID == s.Binding.CommandID || string(i.EnrollmentCommandID) != plan.OTP.ChallengeID {
		return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
	}
	fields, err := PhoneVerificationFields(i)
	if err != nil {
		return PhoneVerificationIntent{}, nil, err
	}
	seen := make(map[string]bool, len(fields))
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "phone-verification.") {
			continue
		}
		if seen[actual.Name] {
			return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
		}
		found := false
		for _, expected := range fields {
			if actual.Name == expected.Name {
				a, ea := encodeFeatureValue(actual.Value)
				b, eb := encodeFeatureValue(expected.Value)
				if actual.Value.Kind != expected.Value.Kind || ea != nil || eb != nil || !bytes.Equal(a, b) {
					return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
				}
				found, seen[actual.Name] = true, true
				break
			}
		}
		if !found {
			return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
		}
	}
	if len(seen) != len(fields) {
		return PhoneVerificationIntent{}, nil, invalidPhoneVerification()
	}
	return i, d, nil
}

type phoneVerificationProgress struct {
	intent   PhoneVerificationIntent
	domain   *PhoneEnrollmentDomain
	before   identity.IdentifierState
	mutation identity.IdentifierMutation
	at       time.Time
	applied  bool
}

func phoneVerificationTarget(state identity.IdentifierState, i PhoneVerificationIntent) bool {
	if state.User.Version != i.Change.ExpectedUserVersion || state.AuthorityVersion != i.Change.ExpectedAuthorityVersion {
		return false
	}
	for _, a := range state.Identifiers {
		if a.ID == i.Change.ID && a.Kind == identity.IdentifierPhone && a.CanonicalValue == i.CanonicalNumber &&
			a.NormalizationProfile == i.NormalizationProfile && a.NormalizationVersion == i.NormalizationVersion &&
			a.Version == 1 && !a.Verified && !a.Primary {
			for _, v := range state.Verifications {
				if v.IdentifierID == a.ID && v.Version == 1 && v.State == identity.VerificationPending && v.VerifiedAt.IsZero() {
					return true
				}
			}
		}
	}
	return false
}

// RequirePhoneVerificationTarget locks the exact original pending partition in
// the synchronous input-admission phase, before any code comparison/debit.
// Acquire this user lock before credential/session/factor locks, avoiding lock
// upgrades. No mutation, generation, external IO or proof renewal occurs.
// Foreign invocation, target or predecessor poisons the existing Work.
func (w Work) RequirePhoneVerificationTarget(ctx context.Context, owner PhoneVerificationContributor, command identity.Command) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidPhoneVerification())
	}
	b, registration, _, err := w.FeatureScope(owner)
	p := w.state.featurePreparationPlan
	if err != nil || p == nil || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != command ||
		p.binding != b || registration.Operation != phoneVerificationOperation() {
		return w.fail(ctx, invalidPhoneVerification())
	}
	i, d, err := phoneVerificationCommand(owner, command, p.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	matched := false
	for _, entry := range p.contributors {
		if repository, ok := entry.contributor.(*Repository); ok && repository == d.repository {
			matched = true
		}
	}
	if !matched {
		return w.fail(ctx, invalidPhoneVerification())
	}
	state, _, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	if !phoneVerificationTarget(state, i) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}

func preparePhoneVerification(ctx context.Context, w Work, command identity.Command) error {
	p := w.state.execution.reservation.plan
	var phase PhoneVerificationContributor
	var repository *Repository
	for _, entry := range p.contributors {
		if entry.descriptor == p.feature.Contributor {
			phase, _ = entry.contributor.(PhoneVerificationContributor)
		}
		if entry.descriptor.Owner == "identity/postgres" {
			repository, _ = entry.contributor.(*Repository)
		}
	}
	if phase == nil || repository == nil || w.state.phoneVerification != nil {
		return w.fail(ctx, invalidPhoneVerification())
	}
	i, d, err := phoneVerificationCommand(phase, command, p.snapshot())
	if err != nil || d == nil || d.repository != repository {
		return w.fail(ctx, invalidPhoneVerification())
	}
	before, now, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	if !phoneVerificationTarget(before, i) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	mutation, err := identity.ApplyIdentifierChange(before, i.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	w.state.phoneVerification = &phoneVerificationProgress{intent: i, domain: d, before: before, mutation: mutation, at: now}
	return nil
}

func applyPhoneVerification(ctx context.Context, w Work) error {
	p := w.state.phoneVerification
	if p == nil || p.applied || w.state.otpCommand == nil {
		return w.fail(ctx, invalidPhoneVerification())
	}
	if err := w.state.execution.coordinator.runOTPExecution(ctx, w, *w.state.otpCommand, otpCheck); err != nil {
		return err
	}
	if err := persistIdentifierMutation(ctx, w, w.state.binding, p.intent.Change, p.before, p.mutation, p.domain.reuse, p.at); err != nil {
		return err
	}
	p.applied = true
	return nil
}

// Map only this Work's own persisted identifier successor. The native owner
// supplies the authenticated enrollment successor (not today's observed epoch);
// verification may advance it once more without renewing any other authority.
func otpPhoneVerificationCredential(w Work, b identity.CommandBinding, original CredentialAdmission) (CredentialAdmission, error) {
	if w.state == nil || w.state.feature == nil || w.state.feature.Operation != phoneVerificationOperation() ||
		w.state.phoneVerification == nil || !w.state.phoneVerification.applied {
		return original, nil
	}
	p := w.state.phoneVerification
	if w.state.binding != b || original.IdentifierAuthorityVersion != p.before.AuthorityVersion ||
		p.before.AuthorityVersion == ^uint64(0) || p.mutation.State.AuthorityVersion != p.before.AuthorityVersion+1 ||
		p.before.User.Version == ^uint64(0) || p.mutation.State.User.Version != p.before.User.Version+1 ||
		p.intent.Change.TenantID != b.TenantID || p.intent.Change.UserID != b.UserID || string(p.intent.Change.ID) != b.RecordID {
		return CredentialAdmission{}, invalidPhoneVerification()
	}
	original.IdentifierAuthorityVersion = p.mutation.State.AuthorityVersion
	return original, nil
}

func otpMutationCredential(w Work, b identity.CommandBinding, original CredentialAdmission) (CredentialAdmission, error) {
	if w.state != nil && w.state.feature != nil && w.state.feature.Operation == phoneChangeOperation() {
		return otpPhoneChangeCredential(w, b, original)
	}
	if w.state != nil && w.state.feature != nil && w.state.feature.Operation == phoneVerificationOperation() {
		return otpPhoneVerificationCredential(w, b, original)
	}
	return otpEmailVerificationCredential(w, b, original)
}

func otpMutationUser(w Work, b identity.CommandBinding, original UserAuthorityAdmission) (UserAuthorityAdmission, error) {
	mapped, err := otpMutationCredential(w, b, CredentialAdmission{IdentifierAuthorityVersion: original.IdentifierAuthorityVersion})
	if err != nil {
		return UserAuthorityAdmission{}, err
	}
	original.IdentifierAuthorityVersion = mapped.IdentifierAuthorityVersion
	return original, nil
}

func recoverPhoneVerification(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	// Current rows never prove historical success. Negative evidence requires
	// the still-original pending target; all enlisted owners must also agree.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers i WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3 AND i.kind='phone' AND i.version=1 AND i.verification_version=1 AND i.verification_state=1 AND NOT i.verified AND NOT i.is_primary AND NOT EXISTS(SELECT 1 FROM identity.identifier_retirements r WHERE r.tenant_id=i.tenant_id AND r.identifier_id=i.identifier_id))`, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var unchanged bool
	if !rows.Next() || rows.Scan(&unchanged) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if unchanged {
		return RecoveryNotCommitted, nil
	}
	return RecoveryUnknown, nil
}

// Format redacts phone and original account/command correlations.
func (PhoneVerificationIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PhoneVerificationIntent(redacted)"))
}

// MarshalJSON denies implicit export of protected intent.
func (PhoneVerificationIntent) MarshalJSON() ([]byte, error) { return nil, invalidPhoneVerification() }
