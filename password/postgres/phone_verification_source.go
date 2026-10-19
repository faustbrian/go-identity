package passwordpostgres

import (
	"context"
	"crypto/hmac"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// PhoneVerificationSession authenticates token possession of the named retained
// session for transport subject/CSRF mapping, even after this flow's identifier
// epoch changes. This is not ordinary session.Get/validation and does not renew
// active authority, lifetime or proof freshness. Send/Verify independently fence
// all current authority; recovery independently authorizes original history.
// Returned session metadata is private original provenance, never a response.
func (s *PhoneVerificationService) PhoneVerificationSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	p := s.state()
	if ctx == nil || p == nil {
		return session.Session{}, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	return p.possessedPhoneSession(ctx, tenant, flow)
}
func (s *phoneVerificationService) possessedPhoneSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return session.Session{}, password.ErrPasswordWork
	}
	kind, id, bearer, err := flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationAuthenticatedSession {
		return session.Session{}, password.ErrPasswordWork
	}
	row, err := s.primary.primary.source.sessions.Get(ctx, tenant, id)
	if err != nil {
		return session.Session{}, readerFailure(ctx)
	}
	b, err := row.Session.Bindings()
	if err != nil || b.TenantID != tenant || b.SessionID != id || b.Authentication.Kind != session.AuthenticationVerified || b.Authentication.Proof.Method != "password" || b.Authentication.CredentialID == "" {
		return session.Session{}, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return session.Session{}, identity.ForbiddenError{}
	}
	matched := false
	for _, key := range s.primary.primary.source.c.LookupKeys {
		actual, e := token.Digest(key, string(tenant))
		if e == nil && actual.KeyVersion == b.Lookup.KeyVersion && hmac.Equal(actual.Sum[:], b.Lookup.Sum[:]) {
			matched = true
		}
	}
	if !matched {
		return session.Session{}, identity.ForbiddenError{}
	}
	return row.Session, ctx.Err()
}
func (s *phoneVerificationService) checkCSRF(original session.Session, token session.CSRFToken) error {
	switch s.primary.primary.config.Transport {
	case session.CredentialBearer:
		if token != (session.CSRFToken{}) {
			return identity.ForbiddenError{}
		}
		return nil
	case session.CredentialCookie:
		return (passwordChangeCSRF{keys: s.primary.primary.config.CSRFKeys}).checkSession(original, token)
	default:
		return password.ErrPasswordWork
	}
}
func (s *phoneVerificationService) requireCSRF(ctx context.Context, w kernel.Work, original session.Session, token session.CSRFToken) error {
	if err := s.checkCSRF(original, token); err != nil {
		return err
	}
	if s.primary.primary.config.Transport == session.CredentialBearer {
		return nil
	}
	b, err := original.CSRFState().Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	for _, key := range s.primary.primary.config.CSRFKeys {
		if key.Version() == b.KeyVersion {
			return sessionpg.RequireCSRF(ctx, w, s.primary.primary.source.c.Session, original, token, key)
		}
	}
	return identity.ForbiddenError{}
}

func (s *phoneVerificationService) restorePhoneSource(ctx context.Context, tenant identity.TenantID, user identity.UserID, caller authorization.DecisionContext, flow otp.SendFlow, send identity.CommandID, csrf session.CSRFToken) (*phoneEnrollmentPhase, otppg.PhoneEnrollmentConfirmation, error) {
	bad := func(err error) (*phoneEnrollmentPhase, otppg.PhoneEnrollmentConfirmation, error) {
		return nil, otppg.PhoneEnrollmentConfirmation{}, err
	}
	kind, flowID, bearer, err := flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationAuthenticatedSession {
		return bad(password.ErrPasswordWork)
	}
	actual, err := s.possessedPhoneSession(ctx, tenant, flow)
	if err != nil {
		return bad(err)
	}
	current, e := actual.Bindings()
	if e != nil || current.UserID != user || s.checkCSRF(actual, csrf) != nil {
		return bad(identity.ForbiddenError{})
	}
	candidate, err := phoneEnrollmentIdentifier(send)
	if err != nil {
		return bad(err)
	}
	q := identity.RecoveryQuery{TenantID: tenant, UserID: user, CommandID: send, RecordID: string(candidate), ActorKind: authorization.SubjectUser, ActorID: identity.ActorID(user), OperationID: phoneEnrollmentOperation().OperationID}
	p := &phoneEnrollmentPhase{service: s}
	coordinator, _, err := s.coordinator(p, nil)
	if err != nil {
		return bad(err)
	}
	record, err := coordinator.QueryPreparedFeature(ctx, q, s.phoneQueryCaller(caller, q, true), kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: phoneEnrollmentOperation()}, p)
	if err != nil {
		return bad(err)
	}
	defer clear(record.InputCiphertext)
	defer clear(record.OutputCiphertext)
	source, _, err := s.readEnrollmentInput(ctx, record.InputBinding, record.InputCiphertext, bearer, caller, csrf)
	if err != nil {
		return bad(err)
	}
	original, err := source.primary.Original()
	if err != nil {
		return bad(err)
	}
	b, err := original.Bindings()
	if err != nil || b.TenantID != tenant || b.UserID != user || b.SessionID != flowID {
		return bad(identity.ForbiddenError{})
	}
	// Committed encrypted custody authenticates history. Do not try to renew
	// expired sending-risk facts merely to restore a consuming or recovery flow.
	output, err := s.readEnrollmentOutput(ctx, sourceBinding(source.command), record.OutputGeneration, record.OutputCiphertext)
	if err != nil {
		return bad(err)
	}
	defer clear(output.OTP)
	confirmation, err := s.config().Issuer.RestoreEnrollmentConfirmation(ctx, source.command, source.input, record.OutputGeneration, output.OTP)
	if err != nil {
		return bad(err)
	}
	return source, confirmation, nil
}

type phoneCurrentAuthority struct {
	Directory                                                       kernel.DirectoryAuthorityAdmission
	Credential                                                      identity.CredentialRef
	User, UserVersion, Identifier, CredentialVersion, Authorization uint64
}

func (s *phoneVerificationService) currentPhoneSource(ctx context.Context, caller authorization.DecisionContext, source *phoneEnrollmentPhase, submission bool) (phoneCurrentAuthority, error) {
	return s.currentPhoneSourceForAction(ctx, caller, source, submission, "identity.phone.verify.recover")
}

func (s *phoneVerificationService) currentPhoneSourceForAction(ctx context.Context, caller authorization.DecisionContext, source *phoneEnrollmentPhase, submission bool, recoveryAction authorization.Action) (phoneCurrentAuthority, error) {
	bad := func(err error) (phoneCurrentAuthority, error) { return phoneCurrentAuthority{}, err }
	b := sourceBinding(source.command)
	original, err := source.primary.Original()
	if err != nil {
		return bad(err)
	}
	d, c, a, err := s.primary.primary.originalAdmission(original, b)
	if err != nil {
		return bad(err)
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, d.Query)
	if err != nil {
		return bad(err)
	}
	status, err := s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: b.TenantID, UserID: b.UserID})
	if err != nil {
		return bad(err)
	}
	identifiers, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return bad(err)
	}
	credential, err := s.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: b.TenantID, UserID: b.UserID, CredentialID: c.Credential.ID})
	if err != nil {
		return bad(err)
	}
	authority, err := s.authorization.Get(ctx, a.Scope)
	if err != nil {
		return bad(readerFailure(ctx))
	}
	now, err := s.now(ctx)
	if err != nil {
		return bad(err)
	}
	if !directory.Enabled || directory.GlobalVersion != d.GlobalVersion || directory.TenantVersion != d.TenantVersion || status.User.Status != identity.StatusActive || identifiers.User.Status != identity.StatusActive || status.User.Version != identifiers.User.Version || status.AuthorityVersion != c.UserAuthorityVersion || authority.Version != a.Version || identity.CheckCredentialAuthority(credential, c.Credential, c.CredentialAuthorityVersion, now) != nil {
		return bad(identity.ForbiddenError{})
	}
	if submission {
		if now.Before(source.at) || !now.Before(source.until) || identifiers.User.Version != source.intent.Change.ExpectedUserVersion+1 || identifiers.AuthorityVersion != source.intent.Change.ExpectedAuthorityVersion+1 {
			return bad(identity.ForbiddenError{})
		}
		found := false
		for _, i := range identifiers.Identifiers {
			if i.ID == source.intent.Change.ID && i.Kind == identity.IdentifierPhone && i.CanonicalValue == source.intent.Change.CanonicalValue && i.NormalizationProfile == source.intent.Change.NormalizationProfile && i.NormalizationVersion == source.intent.Change.NormalizationVersion && i.Version == 1 && !i.Verified && !i.Primary {
				for _, v := range identifiers.Verifications {
					if v.IdentifierID == i.ID && v.Version == 1 && v.State == identity.VerificationPending {
						found = true
					}
				}
			}
		}
		if !found {
			return bad(identity.ForbiddenError{})
		}
	} else {
		// Historical disclosure permits identifier epochs changed by this flow or
		// later authorized work, never a new executable session or OTP authority.
		policy := s.primary.primary.source.c.Coordinator.QueryPolicy
		query := caller.Clone()
		query.PolicyRevision = authorization.Revision(policy.PolicyVersion)
		query.Request.Action = recoveryAction
		query.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
		decision, e := policy.Authorization.Decide(ctx, query)
		if ctx.Err() != nil {
			return bad(ctx.Err())
		}
		if e != nil || decision.Outcome != authorization.Allow || decision.Revision != query.PolicyRevision {
			return bad(identity.ForbiddenError{})
		}
	}
	return phoneCurrentAuthority{Directory: d, Credential: c.Credential, User: status.AuthorityVersion, UserVersion: status.User.Version, Identifier: identifiers.AuthorityVersion, CredentialVersion: credential.AuthorityVersion, Authorization: authority.Version}, nil
}
func phoneRecoveryQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, RecordID: b.RecordID, ActorKind: b.ActorKind, ActorID: b.ActorID, OperationID: b.OperationID}
}
func (s *phoneVerificationService) phoneQueryCaller(c authorization.DecisionContext, q identity.RecoveryQuery, history bool) authorization.DecisionContext {
	c = c.Clone()
	policy := s.primary.primary.source.c.Coordinator.AdmissionPolicy
	if history {
		policy = s.primary.primary.source.c.Coordinator.QueryPolicy
	}
	c.PolicyRevision = authorization.Revision(policy.PolicyVersion)
	c.Request.Action = authorization.Action(q.OperationID)
	c.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}
	return c
}
