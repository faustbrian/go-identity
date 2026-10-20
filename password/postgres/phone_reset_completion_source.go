package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This invocation-local borrow is original committed issuance custody, not
// accepted recovery factors or permission to change a password. Completion's
// sole Work still fences current primary/phone/factor authority and consumes
// its separate completion risk, capability and joint SMS/TOTP attempt.
type phoneResetIssuedRequest struct {
	source    phonePasswordRecoverySelection
	recipient kernel.RecipientRecord
	prepared  otppg.PreparedPhonePasswordResetSend
	origin    password.ResetGrantSpec
	command   identity.Command
}

// origin must already be derived from the real issuer's verified, durably
// attributed phone grant. The kernel supplies original input/output provenance;
// neither signed scalar caveats nor current primary reads can recreate the
// actual issued SMS continuation. Old initiation risk is not reevaluated or
// renewed: it authorized the committed send, not this later mutation.
func (s *phoneResetRequestService) restoreIssuedRequest(ctx context.Context, origin password.ResetGrantSpec, caller authorization.DecisionContext, flow otp.SendFlow) (*phoneResetIssuedRequest, error) {
	if ctx == nil || s == nil || s.primary == nil || caller.Validate() != nil || caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Tenant != authorization.TenantID(origin.TenantID) || caller.Request.Action != "identity.phone.password-reset-complete" || caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != "" || caller.PolicyRevision != authorization.Revision(s.primary.c.Coordinator.AdmissionPolicy.PolicyVersion) || origin.RecoveryPath != auth.RecoveryPathPhone || origin.OriginCommandID != origin.Phone.AttemptID || string(origin.OriginCommandID) != origin.Phone.OTPChallengeID || origin.Phone.NumberKeyVersion != s.c.NumberBindingKeyVersion {
		return nil, identity.ForbiddenError{}
	}
	if _, err := s.link.profile.Payload(origin); err != nil {
		return nil, identity.ForbiddenError{}
	}
	kind, flowID, cookie, err := flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationPreAuthTransaction || flowID != origin.Phone.PreAuthTransaction {
		return nil, identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, s.primary.c.Repository.MaximumDuration)
	defer cancel()
	phase := &phoneResetKeyPhase{service: s}
	coordinator, err := s.coordinator(phase, nil)
	if err != nil {
		return nil, err
	}
	q := identity.RecoveryQuery{CommandID: origin.OriginCommandID, TenantID: origin.TenantID, UserID: origin.UserID, RecordID: string(origin.OriginCommandID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: phoneResetRequestOperation().OperationID}
	queryCaller := caller.Clone()
	queryCaller.Request.Action = authorization.Action(q.OperationID)
	queryCaller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	record, err := coordinator.QueryPreparedFeature(ctx, q, queryCaller, kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: phoneResetRequestOperation()}, phase)
	defer clear(record.InputCiphertext)
	defer clear(record.OutputCiphertext)
	if err != nil {
		return nil, err
	}
	stored, err := s.openOriginalInput(ctx, record.InputBinding, record.InputCiphertext)
	defer clear(stored.FactorEnvelope)
	if err != nil {
		return nil, err
	}
	b := stored.Spec.Binding
	if phoneResetRequestQuery(b) != q {
		return nil, identity.ForbiddenError{}
	}
	selected, err := s.restoreSelection(ctx, stored)
	if err != nil {
		return nil, err
	}
	originalFlow, err := selected.flow.Bindings()
	if err != nil || string(originalFlow.Binding.ID) != flowID {
		return nil, identity.ForbiddenError{}
	}
	current, err := sessionpg.ReadPreAuth(ctx, phoneResetPrimaryRows{s.primary.pool}, s.source.session, origin.TenantID, originalFlow.Binding.ID)
	if err != nil {
		return nil, err
	}
	currentFlow, err := current.Bindings()
	if err != nil || currentFlow != originalFlow {
		return nil, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return nil, identity.ForbiddenError{}
	}
	matched := false
	for _, key := range s.source.flowKeys {
		digest, err := token.PreAuthDigest(key, originalFlow.Binding)
		if err == nil && digest.KeyVersion == originalFlow.Cookie.KeyVersion && hmac.Equal(digest.Sum[:], originalFlow.Cookie.Sum[:]) {
			matched = true
		}
	}
	var now time.Time
	if err = s.primary.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, readerFailure(ctx)
	}
	if !matched || current.Check(now.UTC(), originalFlow.Binding, originalFlow.Cookie) != nil || !now.Before(origin.ExpiresAt) {
		return nil, identity.ForbiddenError{}
	}
	// SMS issuance used its known-user recipient query. Borrow that same query
	// and every original predecessor; a newer primary snapshot cannot replace it.
	query := selected.recipient.Query
	query.UserID = b.UserID
	recipient, err := s.source.directory.ResolveRecipient(ctx, query)
	expected := selected.recipient
	expected.Query, expected.ObservedAt = query, recipient.ObservedAt
	if err != nil || !reflect.DeepEqual(recipient, expected) {
		return nil, identity.ForbiddenError{}
	}
	recipient.ObservedAt = selected.smsObservedAt
	a := otppg.AttemptAuthority{Directory: selected.directory, Credential: selected.credential.Credential, UserAuthorization: selected.policy, UserAuthorityVersion: selected.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: selected.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: selected.recipient.CredentialAuthorityVersion}
	input, err := s.c.SMS.CaptureInput(ctx, b, selected.flow, recipient, a, selected.factor, selected.observedAt, minPhoneResetExpiry(selected.observedAt, originalFlow.Binding.ExpiresAt))
	if err != nil {
		return nil, err
	}
	metadata, err := selected.factor.Metadata()
	if err != nil {
		return nil, err
	}
	at, until, err := input.Timeline()
	if err != nil {
		return nil, err
	}
	expectedOrigin := password.ResetGrantSpec{TenantID: b.TenantID, UserID: b.UserID, CredentialID: a.Credential.ID, CredentialVersion: a.Credential.Version, CredentialAuthorityVersion: a.CredentialAuthorityVersion, UserAuthorityVersion: a.UserAuthorityVersion, IdentifierID: selected.recipient.Identifier.ID, IdentifierVersion: selected.recipient.Identifier.Version, FactorVersion: metadata.FactorAuthorityVersion, OriginCommandID: b.CommandID, RecoveryPath: auth.RecoveryPathPhone, CallbackURL: originalFlow.Binding.Intent.CallbackURL, IssuedAt: at.Truncate(time.Second), ExpiresAt: until.Truncate(time.Second), Phone: password.PhoneResetBinding{PreAuthTransaction: string(originalFlow.Binding.ID), OTPChallengeID: string(b.CommandID), AttemptID: b.CommandID, NumberDigest: originalFlow.Binding.Intent.IdentifierBinding, NumberKeyVersion: s.c.NumberBindingKeyVersion, VerificationVersion: selected.recipient.Verification.Version, FactorID: metadata.FactorID, FactorVersion: metadata.EnrollmentVersion, RiskPolicyVersion: b.PolicyVersion}}
	if expectedOrigin != origin {
		return nil, identity.ForbiddenError{}
	}
	root, err := identity.NewFeaturePreAuthCommand(stored.Spec, cookie)
	if err != nil {
		return nil, err
	}
	outputOwner := &phoneResetRequestPhase{command: root}
	aad, err := outputOwner.aad(record.OutputGeneration)
	if err != nil {
		return nil, err
	}
	sealed, err := envelope.ParseEnvelope(record.OutputCiphertext)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	plain, err := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumKeyedPasswordCustody {
		return nil, password.ErrPasswordWork
	}
	var output phoneResetRequestOutput
	if decodeKeyedPasswordJSON(plain, &output) != nil || output.Schema != 1 || len(output.Plan.Grants) != 1 {
		return nil, password.ErrPasswordWork
	}
	defer clear(output.SMS)
	defer clear(output.Issuance)
	defer clear(output.Delivery)
	prepared, err := s.c.SMS.Restore(ctx, root, input, record.OutputGeneration, output.SMS)
	if err != nil {
		return nil, err
	}
	return &phoneResetIssuedRequest{source: selected, recipient: recipient, prepared: prepared, origin: origin, command: root}, nil
}
