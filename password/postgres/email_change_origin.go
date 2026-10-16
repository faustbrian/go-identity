package passwordpostgres

import (
	"context"
	"crypto/sha256"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

var _ email.ChangeOriginSource = (*EmailManagementService)(nil)

// ReadChangeOrigin authenticates the original committed encrypted change request
// without requiring a delivered link or any new password proof. Current query
// authority controls disclosure; returned provenance is not current mutation
// authority. Original admission and request-validity times remain unchanged, including
// after completion or expiry. Callers must enforce the selected current-session,
// factor, original-validity and primary partition fences before any OTP effects.
//
// No custody is regenerated and no current source is substituted. Temporary
// ciphertext and decoded issuance/delivery buffers are owned and cleared here;
// the pool and caller are borrowed. Immutable composition supports concurrency.
// MaximumDuration/earlier cancellation bound IO. Redacted errors return zero.
func (s *EmailManagementService) ReadChangeOrigin(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out email.ChangeOrigin, err error) {
	if ctx == nil || s == nil || s.primary == nil || s.primary.source == nil || s.config == nil || s.crypto == nil || s.primary.config.Action != "identity.email.change-request" || s.config().Change == nil || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) || q.UserID == "" || q.RecordID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 || (q.OperationID != "identity.otp.email-change-request" && q.OperationID != "identity.otp.email-change-confirm" && q.OperationID != "identity.otp.email-change-confirm.recover") {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = email.ChangeOrigin{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return out, err
	}
	phase := &emailManagementPhase{service: s}
	coordinator, _, err := s.coordinator(phase)
	if err != nil {
		return out, err
	}
	feature := kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: emailPrimaryOperation("identity.email.change-request")}
	binding, wire, generation, err := coordinator.QueryManagedEmailPreparation(ctx, q, caller, feature, phase)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	stored, err := s.readOutput(ctx, binding, generation, wire)
	defer clear(stored.IssuanceWire)
	defer clear(stored.DeliveryWire)
	if err != nil {
		return out, readerFailure(ctx)
	}
	out.Spec, err = s.managedVerificationIntent(stored)
	if err != nil {
		return out, err
	}
	var fields []identity.FeatureField
	for _, f := range stored.Spec.Fields {
		if strings.HasPrefix(f.Name, "source-session.") {
			fields = append(fields, f)
		}
		switch f.Name {
		case "email.management.factor-version", "email-attachment.user-version", "email-attachment.authority-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 || f.Value.Uint64 == ^uint64(0) {
				return out, password.ErrPasswordWork
			}
			switch f.Name {
			case "email.management.factor-version":
				out.FactorVersion = f.Value.Uint64
			case "email-attachment.user-version":
				out.UserVersion = f.Value.Uint64
			case "email-attachment.authority-version":
				out.IdentifierAuthorityVersion = f.Value.Uint64
			}
		}
	}
	out.Session, err = sessionpg.OriginalSessionFromFields(binding.TenantID, binding.UserID, fields)
	if err != nil || out.UserVersion == 0 || out.IdentifierAuthorityVersion == 0 || out.FactorVersion == 0 {
		return out, password.ErrPasswordWork
	}
	_, credential, _, err := sessionpg.OriginalSessionAdmission(s.primary.source.c.Profile, out.Session, binding)
	if err != nil || credential.IdentifierAuthorityVersion != out.IdentifierAuthorityVersion {
		return out, password.ErrPasswordWork
	}
	out.OutputDigest = sha256.Sum256(wire)
	return out, nil
}

// EmailChangeNotificationOwner returns the immutable selected native notice
// participant for trusted composition. It performs no IO and grants no Work or
// mutation permission. Nil means the change profile is unavailable; callers
// must enlist this exact pointer, not another owner with the same descriptor.
func (s *EmailManagementService) EmailChangeNotificationOwner() *deliverypg.Contributor {
	if s == nil || s.config == nil || s.config().ChangeNotification == nil {
		return nil
	}
	return s.config().Delivery.Owner
}

// PrepareOTPChangeNotification reuses the original change owner's notice policy
// after authenticating committed origin under current OTP-confirm disclosure.
// No caller-provided previous mailbox is accepted. The new consuming command
// must bind the same tenant/user/candidate and self actor. This method renders
// and seals only; it neither stages, sends, renews nor authorizes replacement.
// Invoke before opening SQL Work, then stage with EmailChangeNotificationOwner
// in the sole protected commit. Returned custody is private and immutable.
func (s *EmailManagementService) PrepareOTPChangeNotification(ctx context.Context, b identity.CommandBinding, q identity.RecoveryQuery, caller authorization.DecisionContext) (deliverypg.PreparedDelivery, error) {
	return s.prepareOTPChangeNotification(ctx, b, q, caller, false)
}

// PrepareOTPInitialPrimaryNotification selects the original sole verified old
// mailbox for explicitly enabled first-primary OTP establishment. It requires
// an authenticated committed change origin permitting initial-primary policy,
// never a generic pending attachment or a caller-selected old mailbox. It
// renders/seals outside Work; the existing notice owner stages it atomically.
// Existing PrepareOTPChangeNotification remains genuine-primary-only.
func (s *EmailManagementService) PrepareOTPInitialPrimaryNotification(ctx context.Context, b identity.CommandBinding, q identity.RecoveryQuery, caller authorization.DecisionContext) (deliverypg.PreparedDelivery, error) {
	return s.prepareOTPChangeNotification(ctx, b, q, caller, true)
}

func (s *EmailManagementService) prepareOTPChangeNotification(ctx context.Context, b identity.CommandBinding, q identity.RecoveryQuery, caller authorization.DecisionContext, initial bool) (deliverypg.PreparedDelivery, error) {
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-change-confirm", SchemaID: "identity.otp.email-change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if ctx == nil || s == nil || s.EmailChangeNotificationOwner() == nil || b.ValidateFor(op) != nil || b.TenantID != q.TenantID || b.UserID != q.UserID || b.RecordID != q.RecordID || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || q.OperationID != op.OperationID {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	original, err := s.ReadChangeOrigin(ctx, q, caller)
	if err != nil {
		return deliverypg.PreparedDelivery{}, err
	}
	if original.Spec.Previous.Primary == initial || initial && original.Spec.ChangeProfile.CurrentAddress != email.PrimaryOrSoleVerifiedAddress {
		return deliverypg.PreparedDelivery{}, identity.ForbiddenError{}
	}
	return s.prepareChangeNotification(ctx, b, original.Spec)
}
