package postgres

import (
	"context"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func otpEmailVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-verify", SchemaID: "identity.otp.email-verify.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// RequireOTPEmailVerificationTarget serializes the exact original pending-email
// partition before an OTP comparison/debit or protected application. Call after
// frozen directory admission and before credential/factor/session checks. The
// exact registered native input-admission owner must be active; this takes the
// user row exclusively before any shared credential lock to avoid lock-upgrade
// deadlocks. It checks pending target/CAS input but writes nothing, compares no
// code, grants no reservation and retains no handle beyond the existing Work.
func (w Work) RequireOTPEmailVerificationTarget(ctx context.Context, owner ManagedEmailVerificationContributor, command identity.Command) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidEmailVerification())
	}
	b, registration, _, err := w.FeatureScope(owner)
	p := w.state.featurePreparationPlan
	if err != nil || p == nil || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != command || p.binding != b || registration.Operation != otpEmailVerificationOperation() {
		return w.fail(ctx, invalidEmailVerification())
	}
	i, domain, err := managedEmailVerificationCommand(owner, command, p.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	matched := false
	for _, entry := range p.contributors {
		if repository, ok := entry.contributor.(*Repository); ok && repository == domain.repository {
			matched = true
		}
	}
	if !matched {
		return w.fail(ctx, invalidEmailVerification())
	}
	state, _, err := lockIdentifierPartition(ctx, w, i.Change)
	if err != nil {
		return err
	}
	for _, address := range state.Identifiers {
		if address.ID == i.Change.ID && address.Kind == identity.IdentifierEmail && address.CanonicalValue == i.CanonicalAddress && !address.Verified && !address.Primary {
			return nil
		}
	}
	return w.fail(ctx, identity.ForbiddenError{})
}

// Only the kernel's already-persisted, exact in-transaction successor may change
// the identifier epoch seen by OTP's final checks. Original credential, user,
// authorization, session and time evidence stay unchanged; this never renews a
// proof or admits an arbitrary newer snapshot. The original supplied epoch must
// still match the frozen predecessor on every call.
func otpEmailVerificationCredential(w Work, b identity.CommandBinding, original CredentialAdmission) (CredentialAdmission, error) {
	if w.state == nil || w.state.feature == nil || w.state.feature.Operation != otpEmailVerificationOperation() || w.state.managedEmailVerification == nil || !w.state.managedEmailVerification.applied {
		return original, nil
	}
	p := w.state.managedEmailVerification
	if w.state.binding != b || original.IdentifierAuthorityVersion != p.before.AuthorityVersion || p.before.AuthorityVersion == ^uint64(0) || p.mutation.State.AuthorityVersion != p.before.AuthorityVersion+1 || p.before.User.Version == ^uint64(0) || p.mutation.State.User.Version != p.before.User.Version+1 || p.intent.Change.TenantID != b.TenantID || p.intent.Change.UserID != b.UserID || string(p.intent.Change.ID) != b.RecordID {
		return CredentialAdmission{}, invalidEmailVerification()
	}
	original.IdentifierAuthorityVersion = p.mutation.State.AuthorityVersion
	return original, nil
}

func otpEmailVerificationUser(w Work, b identity.CommandBinding, original UserAuthorityAdmission) (UserAuthorityAdmission, error) {
	mapped, err := otpEmailVerificationCredential(w, b, CredentialAdmission{IdentifierAuthorityVersion: original.IdentifierAuthorityVersion})
	if err != nil {
		return UserAuthorityAdmission{}, err
	}
	original.IdentifierAuthorityVersion = mapped.IdentifierAuthorityVersion
	return original, nil
}

// OTPEmailVerificationFields binds the native pending-address transition to one
// independently issued OTP send command and the canonical email_verification_otp
// recovery selector. RequestCommandID must select that OTP send, not an older
// link or attachment request. Include all fields before fingerprinting/reservation.
// This profile never replaces a primary or issues a session. Mapping proves no
// code comparison, current authority, reservation or mutation; the enlisted OTP
// owner and managed-email contributor must establish those in the sole Work.
// Inputs are borrowed synchronously; returned fields are caller-owned.
func OTPEmailVerificationFields(i ManagedEmailVerificationIntent, send identity.CommandID) ([]identity.FeatureField, error) {
	if i.Change.Action != identity.IdentifierVerify || i.Previous != (ManagedEmailPrevious{}) || send != i.RequestCommandID {
		return nil, invalidEmailVerification()
	}
	if _, err := identity.ParseCommandID(string(send)); err != nil {
		return nil, invalidEmailVerification()
	}
	fields, err := ManagedEmailVerificationFields(i)
	if err != nil {
		return nil, err
	}
	return append(fields,
		identity.FeatureField{Name: "email-otp.recovery-path", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "email_verification_otp"}},
		identity.FeatureField{Name: "email-otp.send-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(send)}},
	), nil
}

func validateOTPEmailVerificationScope(s identity.FeatureCommandSpec, plan CommandPlan) error {
	b := s.Binding
	if s.Operation != otpEmailVerificationOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.Feature.Contributor != otpDescriptor() || plan.Capability != nil || plan.OTP == nil || plan.OTP.Mode != OTPConsume || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || plan.Delivery != nil || plan.CapabilityIssuance != nil || plan.Lifecycle == nil || plan.Lifecycle.EventType != "identifier.verified.v1" {
		return invalidEmailVerification()
	}
	var path, send string
	count := 0
	for _, f := range s.Fields {
		if !strings.HasPrefix(f.Name, "email-otp.") {
			continue
		}
		if f.Value.Kind != identity.FeatureText {
			return invalidEmailVerification()
		}
		switch f.Name {
		case "email-otp.recovery-path":
			path = f.Value.Text
		case "email-otp.send-command":
			send = f.Value.Text
		default:
			return invalidEmailVerification()
		}
		count++
	}
	if count != 2 || path != "email_verification_otp" || send != plan.OTP.ChallengeID || send == string(b.CommandID) {
		return invalidEmailVerification()
	}
	if _, err := identity.ParseCommandID(send); err != nil {
		return invalidEmailVerification()
	}
	return nil
}
