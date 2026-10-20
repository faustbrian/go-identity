package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// PasswordResetCompletionRateSource authenticates durably issued original phone
// reset scope, original browser possession and current trusted query policy.
// It returns sensitive budget metadata, never recovery or mutation permission.
// Lifetime is the actual original SMS issued interval, not signed rounded grant
// time, remaining time or current policy TTL. Matching retries remain addressable
// after their own browser/password/factor consumption; completion independently
// retains all current fences. No mutation, debit, comparison, provider work,
// generation, renewal or transaction occurs. Calls are bounded, concurrent-safe
// under immutable borrowed owners and return zero outputs on every error.
func (s *PhonePasswordResetRequestService) PasswordResetCompletionRateSource(ctx context.Context, proof capability.Proof, flow otp.SendFlow, caller authorization.DecisionContext) (user identity.UserID, credential identity.CredentialID, challenge string, lifetime time.Duration, err error) {
	if ctx == nil {
		return "", "", "", 0, password.ErrPasswordWork
	}
	callerContext := ctx
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if callerContext.Err() != nil {
			err = callerContext.Err()
		}
		if err != nil {
			user, credential, challenge, lifetime = "", "", "", 0
		}
	}()
	if s == nil || s.read == nil {
		err = password.ErrPasswordWork
		return
	}
	n := s.read()
	if n == nil || n.primary == nil || n.primary.pool == nil || n.source == nil || n.link.issuer == nil || n.c.SMS == nil || n.crypto == nil {
		err = password.ErrPasswordWork
		return
	}
	ctx, stop := context.WithTimeout(ctx, n.primary.c.Repository.MaximumDuration)
	defer stop()
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	policy := n.primary.c.Coordinator.QueryPolicy
	if policy == nil {
		err = identity.UnavailableError{}
		return
	}
	grant, source, _, e := n.link.issuer.ReadIssuanceOrigin(ctx, n.primary.pool, proof, "identity.phone.password-reset-complete")
	if e != nil {
		err = e
		return
	}
	now := policy.Clock.Now()
	if now.IsZero() {
		err = identity.UnavailableError{}
		return
	}
	origin, e := n.link.profile.ResolveOriginal(grant, now)
	if e != nil || origin.OriginCommandID != source {
		err = identity.ForbiddenError{}
		return
	}
	stored, id, duration, e := n.readOriginalRateSource(ctx, origin, caller, flow)
	defer clear(stored.FactorEnvelope)
	if e != nil {
		err = e
		return
	}
	return stored.Spec.Binding.UserID, stored.Credential.Credential.ID, id, duration, nil
}

// origin has already been verified and attributed by the canonical issuer.
// The returned journal input is historical metadata only; in particular it is
// not a factor snapshot or current recipient/credential/browser admission.
// Caller owns the returned copied encrypted FactorEnvelope and must clear it.
func (s *phoneResetRequestService) readOriginalRateSource(ctx context.Context, origin password.ResetGrantSpec, caller authorization.DecisionContext, flow otp.SendFlow) (stored phoneResetStoredInput, challenge string, lifetime time.Duration, err error) {
	defer func() {
		if err != nil {
			clear(stored.FactorEnvelope)
			stored = phoneResetStoredInput{}
			challenge = ""
			lifetime = 0
		}
	}()
	if ctx == nil || s == nil || s.primary == nil || s.source == nil || s.primary.c.Coordinator.QueryPolicy == nil || caller.Validate() != nil || caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Tenant != authorization.TenantID(origin.TenantID) || caller.Request.Action != "identity.phone.password-reset-complete" || caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != "" || caller.PolicyRevision != authorization.Revision(s.primary.c.Coordinator.QueryPolicy.PolicyVersion) || caller.PolicyRevision != authorization.Revision(s.primary.c.Coordinator.AdmissionPolicy.PolicyVersion) || origin.RecoveryPath != auth.RecoveryPathPhone || origin.OriginCommandID != origin.Phone.AttemptID || string(origin.OriginCommandID) != origin.Phone.OTPChallengeID || origin.Phone.NumberKeyVersion != s.c.NumberBindingKeyVersion {
		err = identity.ForbiddenError{}
		return
	}
	if _, err = s.link.profile.Payload(origin); err != nil {
		err = identity.ForbiddenError{}
		return
	}
	kind, flowID, cookie, e := flow.Bindings()
	if e != nil || kind != otp.FlowAuthorizationPreAuthTransaction || flowID != origin.Phone.PreAuthTransaction {
		err = identity.ForbiddenError{}
		return
	}
	policy := s.primary.c.Coordinator.QueryPolicy
	now := policy.Clock.Now()
	if now.IsZero() {
		err = identity.UnavailableError{}
		return
	}
	if !now.Before(origin.ExpiresAt) {
		err = identity.ForbiddenError{}
		return
	}
	dc := caller.Clone()
	dc.Request.Resource.ID = authorization.ResourceID(origin.UserID)
	dc.Request.Environment.Time = now.UTC()
	decision, e := policy.Authorization.Decide(ctx, dc)
	if e != nil {
		err = identity.UnavailableError{}
		return
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		err = identity.ForbiddenError{}
		return
	}
	phase := &phoneResetKeyPhase{service: s}
	coordinator, e := s.coordinator(phase, nil)
	if e != nil {
		err = e
		return
	}
	q := identity.RecoveryQuery{CommandID: origin.OriginCommandID, TenantID: origin.TenantID, UserID: origin.UserID, RecordID: string(origin.OriginCommandID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: phoneResetRequestOperation().OperationID}
	queryCaller := caller.Clone()
	queryCaller.Request.Action = authorization.Action(q.OperationID)
	queryCaller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	record, e := coordinator.QueryPreparedFeature(ctx, q, queryCaller, kernel.FeatureRegistration{Contributor: phase.Descriptor(), Operation: phoneResetRequestOperation()}, phase)
	defer clear(record.InputCiphertext)
	defer clear(record.OutputCiphertext)
	if e != nil {
		err = e
		return
	}
	stored, err = s.openOriginalInput(ctx, record.InputBinding, record.InputCiphertext)
	if err != nil {
		return
	}
	b := stored.Spec.Binding
	if phoneResetRequestQuery(b) != q {
		err = identity.ForbiddenError{}
		return
	}
	f := stored.Flow
	original, e := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: f.ID, Intent: session.PreAuthIntent{TenantID: f.TenantID, Action: f.Action, Origin: f.Origin, CallbackURL: f.Callback, Nonce: f.Nonce, IdentifierBinding: f.Identifier, PolicyID: f.Policy, PolicyVersion: f.PolicyVersion, Purpose: session.PreAuthPhonePasswordRecovery}, IssuedAt: f.IssuedAt, ExpiresAt: f.ExpiresAt}, Cookie: f.Cookie, Version: f.Version})
	if e != nil || string(f.ID) != flowID {
		err = identity.ForbiddenError{}
		return
	}
	bound, e := original.Bindings()
	if e != nil {
		err = identity.ForbiddenError{}
		return
	}
	// The digest in encrypted input is not bearer possession. Authenticate the
	// presented cookie with its owner against every original pre-auth binding.
	token, e := session.ParseToken(cookie.Token())
	if e != nil {
		err = identity.ForbiddenError{}
		return
	}
	matched := false
	for _, key := range s.source.flowKeys {
		digest, e := token.PreAuthDigest(key, bound.Binding)
		if e == nil && digest.KeyVersion == bound.Cookie.KeyVersion && hmac.Equal(digest.Sum[:], bound.Cookie.Sum[:]) {
			matched = true
		}
	}
	if !matched {
		err = identity.ForbiddenError{}
		return
	}
	r := stored.Recipient
	observed, e := time.Parse(time.RFC3339Nano, r.ObservedAtTime)
	if e != nil {
		err = password.ErrPasswordWork
		return
	}
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), Suppressed: r.Suppressed, User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAt: observed}
	a := otppg.AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.source.global, TenantID: f.TenantID}, GlobalVersion: stored.GlobalVersion, TenantVersion: stored.TenantVersion}, Credential: stored.Credential.Credential, UserAuthorization: kernel.UserAuthorizationAdmission{Scope: authoritypg.AuthorityScope{TenantID: authorization.TenantID(f.TenantID), SubjectID: authorization.SubjectID(b.UserID), PolicyNamespace: s.source.namespace}, Version: stored.AuthorizationVersion}, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion}
	input, e := otppg.NewPhonePasswordResetMetadataInput(original, recipient, a, stored.Factor, stored.FactorEnvelope, stored.ObservedAt, minPhoneResetExpiry(stored.ObservedAt, bound.Binding.ExpiresAt), stored.SMSObservedAt)
	if e != nil {
		err = e
		return
	}
	root, e := identity.NewFeaturePreAuthCommand(stored.Spec, cookie)
	if e != nil {
		err = e
		return
	}
	aad, e := (&phoneResetRequestPhase{command: root}).aad(record.OutputGeneration)
	if e != nil {
		err = e
		return
	}
	sealed, e := envelope.ParseEnvelope(record.OutputCiphertext)
	if e != nil {
		err = password.ErrPasswordWork
		return
	}
	plain, e := s.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if e != nil || len(plain) == 0 || len(plain) > maximumKeyedPasswordCustody {
		err = password.ErrPasswordWork
		return
	}
	var output phoneResetRequestOutput
	if decodeKeyedPasswordJSON(plain, &output) != nil || output.Schema != 1 || len(output.Plan.Grants) != 1 {
		err = password.ErrPasswordWork
		return
	}
	defer clear(output.SMS)
	defer clear(output.Issuance)
	defer clear(output.Delivery)
	id, at, until, e := s.c.SMS.ReadOriginalMetadata(ctx, root, input, record.OutputGeneration, output.SMS)
	if e != nil {
		err = e
		return
	}
	m := stored.Factor
	expected := password.ResetGrantSpec{TenantID: b.TenantID, UserID: b.UserID, CredentialID: a.Credential.ID, CredentialVersion: a.Credential.Version, CredentialAuthorityVersion: a.CredentialAuthorityVersion, UserAuthorityVersion: a.UserAuthorityVersion, IdentifierID: r.Identifier.ID, IdentifierVersion: r.Identifier.Version, FactorVersion: m.FactorAuthorityVersion, OriginCommandID: b.CommandID, RecoveryPath: auth.RecoveryPathPhone, CallbackURL: bound.Binding.Intent.CallbackURL, IssuedAt: at.Truncate(time.Second), ExpiresAt: until.Truncate(time.Second), Phone: password.PhoneResetBinding{PreAuthTransaction: string(bound.Binding.ID), OTPChallengeID: id, AttemptID: b.CommandID, NumberDigest: bound.Binding.Intent.IdentifierBinding, NumberKeyVersion: s.c.NumberBindingKeyVersion, VerificationVersion: r.Verification.Version, FactorID: m.FactorID, FactorVersion: m.EnrollmentVersion, RiskPolicyVersion: b.PolicyVersion}}
	if expected != origin || id != string(b.CommandID) || !until.After(at) {
		err = identity.ForbiddenError{}
		return
	}
	return stored, id, until.Sub(at), nil
}
