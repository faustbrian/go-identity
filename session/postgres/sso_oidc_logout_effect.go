package postgres

import (
	"context"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

const ssoOIDCLogoutSessionUntil = "sso.oidc.logout.session.valid-until"

func ssoOIDCLogoutSessionSpec(source session.Session) (session.SessionSpec, error) {
	deny := session.ErrInvalidSessionCommand
	s, err := source.Bindings()
	if err != nil || s.Version == ^uint64(0) || s.Authentication.Kind != session.AuthenticationVerified || source.MFAAuthentication() != (session.MFAAuthentication{}) {
		return session.SessionSpec{}, deny
	}
	proof := s.Authentication.Proof
	if proof.Method != "sso-oidc" || proof.Purpose != "session-issue" || proof.Assurance != auth.AssuranceSingleFactor {
		return session.SessionSpec{}, deny
	}
	if _, continued := source.CredentialContinuation(); continued {
		return session.SessionSpec{}, deny
	}
	if _, err := source.CSRFState().Bindings(); err != nil {
		return session.SessionSpec{}, deny
	}
	v, err := s.Authority.Bindings()
	if err != nil || !v.Organization.Present || !v.Factor.Present || v.Passkey.Present {
		return session.SessionSpec{}, deny
	}
	return s, nil
}

// SSOOIDCLogoutFields freezes the exact original enterprise session and its
// exclusive validity cutoff. The native owner must obtain this cutoff from
// its original session admission; floor to microseconds, never round up.
// The fields grant no authentication, provider authority or lease renewal.
func SSOOIDCLogoutFields(source session.Session, until time.Time) ([]identity.FeatureField, error) {
	s, err := ssoOIDCLogoutSessionSpec(source)
	if err != nil || !sessionReadTime(until) || until.Nanosecond()%1000 != 0 || !until.After(s.LastActivityAt) {
		return nil, session.ErrInvalidSessionCommand
	}
	life, err := source.Lifetime(s.LastActivityAt)
	if err != nil || until.After(life.ExpiresAt) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(source)
	if err != nil {
		return nil, err
	}
	return append(fields, identity.FeatureField{Name: ssoOIDCLogoutSessionUntil, Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: until.UTC()}}), nil
}

// SSOOIDCLogoutEffect owns only the local single-session mutation within the
// native enterprise SSO coordinator Work. It performs no provider I/O and
// exposes no cookie, redirect, or authority to write other sessions.
type SSOOIDCLogoutEffect struct {
	native Repository
}

// NewSSOOIDCLogoutEffect selects the original enterprise profile without I/O.
// Apply the shared revocation migration before enabling the caller. The caller
// must authenticate the source, match the exact original linked provider and
// atomically retain state, protected logout audit and session lifecycle work.
func NewSSOOIDCLogoutEffect(c Config, admission SSOOIDCSessionAdmission) (*SSOOIDCLogoutEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !admission.valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	return &SSOOIDCLogoutEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration, revokeSSOOIDC: &admission}}, nil
}

func ssoOIDCLogoutFieldsFromCommand(c identity.Command, b identity.CommandBinding) (session.Session, time.Time, error) {
	f, ok := c.Feature()
	deny := func() (session.Session, time.Time, error) {
		return session.Session{}, time.Time{}, session.ErrInvalidSessionCommand
	}
	if !ok || f.Operation != kernel.SSOOIDCLogoutOperation() || f.Binding != b {
		return deny()
	}
	var original []identity.FeatureField
	var until time.Time
	for _, field := range f.Fields {
		switch {
		case strings.HasPrefix(field.Name, originalSessionPrefix):
			original = append(original, field)
		case field.Name == ssoOIDCLogoutSessionUntil:
			if !until.IsZero() || field.Value.Kind != identity.FeatureTime {
				return deny()
			}
			until = field.Value.Time
		case strings.HasPrefix(field.Name, "sso.oidc.logout.session."):
			return deny()
		}
	}
	source, err := OriginalSessionFromFields(b.TenantID, b.UserID, original)
	if err != nil {
		return deny()
	}
	if _, err := SSOOIDCLogoutFields(source, until); err != nil {
		return deny()
	}
	return source, until, nil
}

func ssoOIDCLogoutScopeMatches(b identity.CommandBinding, f kernel.FeatureRegistration, l kernel.LifecyclePlan, source session.Session) bool {
	s, err := ssoOIDCLogoutSessionSpec(source)
	op := kernel.SSOOIDCLogoutOperation()
	return err == nil && f.Operation == op && f.Contributor == kernel.SSOOIDCLogoutDescriptor() && b.ValidateFor(op) == nil &&
		b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(s.UserID) &&
		b.TenantID == s.TenantID && b.UserID == s.UserID && b.RecordID == s.SessionID &&
		l.EventType == "session.revoked.v1" && l.EventIndex == 0 && l.BeforeVersion == s.Version && l.AfterVersion == s.Version+1
}

func (e *SSOOIDCLogoutEffect) intent(w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) (identity.CommandBinding, kernel.FeatureRegistration, kernel.LifecyclePlan, session.Session, time.Time, error) {
	b, f, l, err := w.FeatureScope(owner)
	source, until, recordErr := ssoOIDCLogoutFieldsFromCommand(c, b)
	if err != nil || recordErr != nil || !ssoOIDCLogoutScopeMatches(b, f, l, source) {
		return identity.CommandBinding{}, kernel.FeatureRegistration{}, kernel.LifecyclePlan{}, session.Session{}, time.Time{}, session.ErrInvalidSessionCommand
	}
	return b, f, l, source, until, nil
}

// Apply requires original Work command custody, current authority and the
// original session's CSRF. Errors abort the sole coordinator transaction;
// a returned receipt is provisional until the command commits.
func (e *SSOOIDCLogoutEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, token session.CSRFToken, key session.CSRFKey) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.native.revokeSSOOIDC == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, f, l, source, until, err := e.intent(w, owner, c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.native.maximumDuration)
	defer stop()
	if err := requireOriginalSessionWindow(bounded, w, source, until); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return e.native.applySingleSessionRevocationWithCSRF(bounded, w, owner, b, f, l, source, &revokeCSRFInput{token: token, key: key})
}

// Check fences the exact terminal record, unchanged family, original linked
// credential and current membership before commit. It never re-authenticates
// the revoked bearer or resets the original validity deadline.
func (e *SSOOIDCLogoutEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || e == nil || e.native.revokeSSOOIDC == nil {
		return session.ErrInvalidSessionCommand
	}
	b, _, l, source, until, err := e.intent(w, owner, c)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.native.maximumDuration)
	defer stop()
	if err := e.native.requireRevokeRecordAuthorityFor(bounded, w, owner, source, b); err != nil {
		return err
	}
	if err := e.native.requireCommittedSingleSessionRevocation(bounded, w, b, l, source); err != nil {
		return err
	}
	if err := e.native.requireRevokeOrganization(bounded, w, owner, b, source); err != nil {
		return err
	}
	return requireOriginalSessionWindow(bounded, w, source, until)
}

// Recover votes from the retained original session journal. It never replays
// local revocation or decides the provider outcome. A missing/mismatched store
// fails closed, rather than restoring proof or acquiring another time window.
func (e *SSOOIDCLogoutEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, source session.Session) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.native.revokeSSOOIDC == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || !ssoOIDCLogoutScopeMatches(b, f, l, source) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.native.maximumDuration)
	defer stop()
	id, _ := revocationEvidence(b, l)
	rows, err := w.Query(bounded, oidcEndSessionEvidenceSQL(e.native.schema), string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	return readOIDCEndSessionEvidence(rows, b, l, source)
}
