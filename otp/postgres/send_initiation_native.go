package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

var _ kernel.RequestKeyPreparationContributor = (*Contributor)(nil)

// The immutable native owner borrows a primary pool and composes existing
// readers. It creates no schema, goroutine, policy service or replay store.
// Register this exact returned pointer with the kernel coordinator.
func newSendInitiationContributor(store *Contributor, pool *database.Pool, c sendInitiationConfig) (*Contributor, error) {
	if store == nil || store.send == nil || store.codec == nil || pool == nil || pool.Raw() == nil || store.preauth == nil && store.session == nil {
		return nil, ErrInvalidConfiguration
	}
	p, err := newSendInitiationProfile(store.send.configuration, c)
	if err != nil {
		return nil, err
	}
	p.pool = pool
	p.kernel, err = kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.maximumDuration})
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	p.authorization, err = authoritypg.NewAuthorityStore(pool.Raw(), c.maximumDuration)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	if store.session != nil {
		p.sessions, err = sessionpg.NewRepository(pool, store.session.store)
		if err != nil {
			return nil, ErrInvalidConfiguration
		}
	}
	fresh := *store
	fresh.initiation = p
	return &fresh, nil
}

// PrepareRequestKey freezes bounded primary records before OTP/risk generation.
// It may run for competing candidates; the kernel persists the sole winner.
// It neither authenticates bearer possession nor grants live authority. Matching
// retries skip this callback and retain the original records and timestamps.
// No challenge, counter, flow reservation, delivery or command journal is written.
func (p *Contributor) PrepareRequestKey(parent context.Context, k kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if parent == nil || p == nil || p.initiation == nil || p.initiation.pool == nil || p.initiation.kernel == nil || p.initiation.authorization == nil {
		return nil, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(parent, p.initiation.config.maximumDuration)
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aad, err := p.sendInitiationAAD(k)
	if err != nil {
		return nil, err
	}
	r, err := p.readSendRequestIntent(intent)
	if err != nil {
		return nil, err
	}
	subject := identity.FeatureSubjectUser
	if r.userID == "" {
		subject = identity.FeatureSubjectAnonymousFlow
	}
	if k.Feature.Operation != issuanceOperation(subject) {
		return nil, ErrInvalidCommand
	}
	profile, _, err := p.send.policy.Bindings()
	if err != nil || profile.Purpose != r.purpose {
		return nil, ErrInvalidCommand
	}
	b := identity.CommandBinding{CommandID: k.Admission.CommandID, TenantID: k.Scope.TenantID, UserID: r.userID, ActorID: k.Scope.ActorID, ActorKind: k.Scope.ActorKind, OperationID: k.Feature.Operation.OperationID, PolicyID: p.initiation.config.policyID, PolicyVersion: p.initiation.config.policyVersion, SchemaID: k.Feature.Operation.SchemaID, SchemaVersion: k.Feature.Operation.SchemaVersion, CorrelationID: string(k.Admission.CommandID), RecordID: string(k.Admission.CommandID)}
	if r.userID == "" {
		b.AnonymousFlowID = r.flowID
	}
	if !initiationBindingMatches(b, k) {
		return nil, ErrInvalidCommand
	}
	flow, remember, flowExpiry, originalSession, err := p.readInitiatingFlow(ctx, b, r)
	if err != nil {
		return nil, err
	}
	a, err := p.readInitiatingAuthority(ctx, b)
	if err != nil {
		return nil, err
	}
	if r.flowKind == otp.FlowAuthorizationAuthenticatedSession {
		_, credential, _, e := sessionpg.OriginalSessionAdmission(p.session.profile, originalSession, b)
		if e != nil {
			return nil, ErrInvalidCommand
		}
		a.Credential = credential.Credential
		if p.sessionAuthority(originalSession, b, a) != nil {
			return nil, identity.ForbiddenError{}
		}
	}
	kind := identity.IdentifierEmail
	if r.channel == otp.ChannelSMS {
		kind = identity.IdentifierPhone
	}
	eligibility := kernel.RecipientVerified
	if r.purpose == otp.PurposeEmailVerification || r.purpose == otp.PurposeEmailChange {
		eligibility = kernel.RecipientPendingOrVerified
	}
	recipient, err := p.initiation.kernel.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: b.TenantID, UserID: b.UserID, Kind: kind, CanonicalValue: r.destination.Value(), Eligibility: eligibility})
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err := p.initiation.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, custodyFailure(ctx)
	}
	now = now.UTC().Truncate(time.Microsecond)
	if !nativeTime(now) || !now.Before(flowExpiry) {
		return nil, identity.ForbiddenError{}
	}
	if r.flowKind == otp.FlowAuthorizationAuthenticatedSession && p.sessionTime(originalSession, now) != nil {
		return nil, identity.ForbiddenError{}
	}
	expires := now.Add(profile.TTL)
	if flowExpiry.Before(expires) {
		expires = flowExpiry
	}
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(b.TenantID), SubjectID: string(b.UserID), Purpose: r.purpose, Channel: r.channel, Destination: r.destination, ChallengeID: b.RecordID, TargetID: r.target, PolicyVersion: b.PolicyVersion, Generation: 1}, flow, remember)
	if err != nil {
		return nil, ErrInvalidCommand
	}
	record := sendRequestRecord{continuation: continuation, policy: p.send.policy, authority: a, issuedAt: now, expiresAt: expires}
	if !recipient.Suppressed {
		record.recipient = &recipient
	}
	mac := hmac.New(sha256.New, p.initiation.config.identifierKey[:])
	frame := []byte("identity-otp-initiating-identifier-v1\x00")
	for _, value := range []string{string(b.TenantID), string(r.channel), r.destination.Value()} {
		frame = appendAuthorityText(frame, value)
	}
	_, _ = mac.Write(frame)
	clear(frame)
	risk := sendInitiationRisk{network: r.network, device: r.device, identifierDigest: hex.EncodeToString(mac.Sum(nil))}
	return p.sealSendInitiationRecord(ctx, aad, record, b, risk, recipient.Suppressed)
}

func (p *Contributor) readInitiatingFlow(ctx context.Context, b identity.CommandBinding, r sendInitiatingRequest) (otp.FlowAuthorization, session.RememberPolicy, time.Time, session.Session, error) {
	bad := func(err error) (otp.FlowAuthorization, session.RememberPolicy, time.Time, session.Session, error) {
		return otp.FlowAuthorization{}, session.RememberPolicy{}, time.Time{}, session.Session{}, err
	}
	if r.flowKind == otp.FlowAuthorizationPreAuthTransaction {
		if p.preauth == nil {
			return bad(ErrInvalidCommand)
		}
		original, err := sessionpg.ReadPreAuth(ctx, p.initiation.pool.Raw(), p.preauth.config, b.TenantID, identity.PreAuthTransactionID(r.flowID))
		if err != nil {
			return bad(err)
		}
		binding, err := original.Bindings()
		if err != nil || binding.Binding.Intent.Action != p.initiation.config.preAuthAction {
			return bad(identity.ForbiddenError{})
		}
		flow, err := otp.NewBoundPreAuthAuthorization(original)
		if err != nil {
			return bad(ErrInvalidCommand)
		}
		var remember session.RememberPolicy
		if r.purpose == otp.PurposeSignin || r.purpose == otp.PurposeMFA {
			remember = binding.Binding.Intent.Remember
		}
		return flow, remember, binding.Binding.ExpiresAt, session.Session{}, nil
	}
	if p.session == nil || p.initiation.sessions == nil {
		return bad(ErrInvalidCommand)
	}
	stored, err := p.initiation.sessions.Get(ctx, b.TenantID, r.flowID)
	if err != nil {
		return bad(err)
	}
	spec, err := stored.Session.Bindings()
	if err != nil || spec.UserID != b.UserID || stored.Revoked || stored.FamilyRevoked || stored.CurrentFamilyVersion != spec.FamilyVersion {
		return bad(identity.ForbiddenError{})
	}
	flow, err := otp.NewBoundSessionAuthorization(stored.Session)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	remember, err := spec.Remember.Bindings()
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	expires := spec.IssuedAt.Add(remember.AbsoluteTTL)
	for _, limit := range []time.Time{spec.LastActivityAt.Add(remember.IdleTTL), spec.Authentication.Proof.IssuedAt.Add(remember.FreshFor), spec.Authentication.Proof.IssuedAt.Add(p.session.freshness)} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	return flow, session.RememberPolicy{}, expires, stored.Session, nil
}

func (p *Contributor) readInitiatingAuthority(ctx context.Context, b identity.CommandBinding) (AttemptAuthority, error) {
	bad := func(err error) (AttemptAuthority, error) { return AttemptAuthority{}, err }
	d, err := p.initiation.kernel.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.global, TenantID: b.TenantID})
	if err != nil {
		return bad(err)
	}
	if !d.Enabled {
		return bad(identity.ForbiddenError{})
	}
	a := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: d.Query, GlobalVersion: d.GlobalVersion, TenantVersion: d.TenantVersion}}
	if b.UserID == "" {
		return a, nil
	}
	status, err := p.initiation.kernel.GetStatus(ctx, identity.UserStatusQuery{TenantID: b.TenantID, UserID: b.UserID})
	if err != nil {
		return bad(err)
	}
	identifiers, err := p.initiation.kernel.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return bad(err)
	}
	if status.User.Status != identity.StatusActive || identifiers.User.Status != identity.StatusActive {
		return bad(identity.ForbiddenError{})
	}
	// Passwordless users have no credential reference to select. Read only the
	// existing kernel user-wide epoch; never fabricate an exact credential or a
	// default epoch. The kernel remains the write/admission authority for it.
	var raw string
	if err := p.initiation.pool.Raw().QueryRow(ctx, `SELECT credential_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)).Scan(&raw); err != nil {
		return bad(custodyFailure(ctx))
	}
	credential, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || credential == 0 || strconv.FormatUint(credential, 10) != raw {
		return bad(identity.UnavailableError{})
	}
	scope := authoritypg.AuthorityScope{TenantID: authorization.TenantID(b.TenantID), SubjectID: authorization.SubjectID(b.UserID), PolicyNamespace: p.namespace}
	u, err := p.initiation.authorization.Get(ctx, scope)
	if err != nil {
		return bad(custodyFailure(ctx))
	}
	a.UserAuthorityVersion, a.IdentifierAuthorityVersion, a.CredentialAuthorityVersion = status.AuthorityVersion, identifiers.AuthorityVersion, credential
	a.UserAuthorization = kernel.UserAuthorizationAdmission{Scope: scope, Version: u.Version}
	if err := a.validate(b); err != nil {
		return bad(err)
	}
	return a, nil
}
