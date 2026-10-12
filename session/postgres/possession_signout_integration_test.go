//go:build integration

package postgres

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Existing owner-local records are deliberate fixtures: this proves primary
// reading and transactional self-signout, not magic-link delivery or issuance.
func testSelectedPossessionSignOut(t *testing.T, ctx context.Context, pool *database.Pool, c OTPSessionServiceConfig, original session.Session) {
	magic := MagicLinkAdmissionConfig(c.Profile)
	selection := SingleFactorSessionAdmissionConfig{OTP: &c.Profile, MagicLink: &magic}
	validation := c.Validation
	validation.Clock = clock.System{}
	reader, err := NewSingleFactorSessionService(pool, SingleFactorSessionServiceConfig{Repository: c.Repository, Admission: selection, Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	csrfKey, _ := session.NewCSRFKey(7, make([]byte, 32))
	execution := IssueExecutorConfig{Repository: c.Repository, Profile: IssueAdmissionConfig{GlobalAuthorityID: c.Profile.GlobalAuthorityID, PolicyNamespace: c.Profile.PolicyNamespace, Audience: c.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, Authorization: revokeQueryPolicy{}, Clock: clock.System{}, PolicyID: "session-policy", PolicyVersion: 1, AuditRetentionVersion: 1}
	config := RevokeOneExecutorConfig{Execution: execution, Sessions: reader, Admission: &selection}
	bearer, err := NewRevokeOneExecutor(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := NewCookieRevokeOneExecutor(pool, config, []session.CSRFKey{csrfKey})
	if err != nil {
		t.Fatal(err)
	}
	policy := session.SignOutConfig{Cookie: cookie, PolicyID: execution.PolicyID, PolicyVersion: 1, MaximumDuration: 2 * time.Second}
	publicBearer, err := session.NewSignOutService(reader, bearer, policy)
	if err != nil {
		t.Fatal(err)
	}
	baseCookie, err := session.NewSignOutService(reader, strict, policy)
	if err != nil {
		t.Fatal(err)
	}
	publicCookie, err := session.NewCookieSignOutService(baseCookie, []session.CSRFKey{csrfKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []session.AuthenticationKind{session.AuthenticationOTP, session.AuthenticationMagicLink} {
		for _, transport := range []session.CredentialKind{session.CredentialBearer, session.CredentialCookie} {
			t.Run(fmt.Sprintf("%d/%d", kind, transport), func(t *testing.T) {
				s, _ := original.Bindings()
				s.SessionID, s.FamilyID = fmt.Sprintf("selected-session-%d-%d", kind, transport), fmt.Sprintf("selected-family-%d-%d", kind, transport)
				s.Authentication = session.AuthenticationMetadata{Kind: kind}
				token, _ := session.NewToken(32)
				s.Lookup, _ = token.Digest(validation.LookupKeys[0], string(s.TenantID))
				a, _ := s.Authority.Bindings()
				keys, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
				a.Session.ScopeKey, a.SessionFamily.ScopeKey = keys.Session, keys.Family
				s.Authority, _ = session.NewAuthoritySnapshot(a)
				csrf, _ := session.NewCSRFToken()
				state, _ := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version})
				var record session.Session
				if kind == session.AuthenticationOTP {
					record, err = session.NewSessionWithOTPAndCSRF(s, original.OTPAuthentication(), state)
				} else {
					p, _ := original.OTPAuthentication().Bindings()
					m, _ := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: p.CommandID, RequestCommandID: p.SendCommandID, CapabilityID: "original-grant", IdentifierID: p.IdentifierID, IdentifierVersion: p.IdentifierVersion, VerificationVersion: p.VerificationVersion, AuthenticatedAt: p.AuthenticatedAt, ValidUntil: p.ValidUntil})
					record, err = session.NewSessionWithMagicLinkAndCSRF(s, m, state)
				}
				if err != nil {
					t.Fatal(err)
				}
				payload, expiry, err := encodeRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(s.TenantID), s.FamilyID, string(s.UserID), s.IssuedAt.UTC().Format(storedTimeLayout)); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8::jsonb)`, string(s.TenantID), s.SessionID, string(s.UserID), s.FamilyID, int64(s.Lookup.KeyVersion), s.Lookup.Sum[:], expiry, payload); err != nil {
					t.Fatal(err)
				}
				credential, _ := session.NewCredential(transport, token)
				input := session.GetRequest{TenantID: s.TenantID, Credential: credential}
				if got, err := reader.Get(ctx, input); err != nil || !got.Authenticated {
					t.Fatal("selected primary reader", err)
				}
				id, _ := identity.NewCommandID()
				r := session.SignOutRequest{TenantID: s.TenantID, CommandID: id, CorrelationID: "selected-signout", Transport: transport, Credential: credential}
				var result session.SignOutResult
				if transport == session.CredentialCookie {
					wrong, _ := session.NewCSRFToken()
					denied, denial := publicCookie.SignOut(ctx, r, wrong)
					if denial == nil || denied.CommitOutcome == identity.CommitOutcomeCommitted {
						t.Fatal("possession cookie logout accepted foreign CSRF")
					}
					if got, err := reader.Get(ctx, input); err != nil || !got.Authenticated {
						t.Fatal("CSRF denial revoked the session", err)
					}
				}
				// Failure after the native mutation must roll back that mutation
				// and lifecycle effects, not merely return an error to the caller.
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_possession_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test rejection';END$$; CREATE TRIGGER reject_possession_audit BEFORE INSERT ON audit.identity_command_bindings FOR EACH ROW EXECUTE FUNCTION public.reject_possession_audit()`); err != nil {
					t.Fatal(err)
				}
				if transport == session.CredentialCookie {
					result, err = publicCookie.SignOut(ctx, r, csrf)
				} else {
					result, err = publicBearer.SignOut(ctx, r)
				}
				if _, cleanup := pool.Raw().Exec(ctx, `DROP TRIGGER reject_possession_audit ON audit.identity_command_bindings; DROP FUNCTION public.reject_possession_audit()`); cleanup != nil {
					t.Fatal(cleanup)
				}
				if err == nil || result.CommitOutcome == identity.CommitOutcomeCommitted {
					t.Fatal("audit failure reported a committed logout")
				}
				if got, err := reader.Get(ctx, input); err != nil || !got.Authenticated {
					t.Fatal("audit failure did not roll back native logout", err)
				}
				var abortedEffects int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1)+(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, id)).Scan(&abortedEffects); err != nil || abortedEffects != 0 {
					t.Fatal("aborted logout retained protected effects", err)
				}
				id, _ = identity.NewCommandID()
				r.CommandID = id
				if transport == session.CredentialCookie {
					result, err = publicCookie.SignOut(ctx, r, csrf)
				} else {
					result, err = publicBearer.SignOut(ctx, r)
				}
				if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted {
					t.Fatal("native possession logout", err)
				}
				if got, err := reader.Get(ctx, input); err != nil || got.Authenticated {
					t.Fatal("logout left bearer active", err)
				}
				if transport == session.CredentialCookie {
					result, err = publicCookie.SignOut(ctx, r, csrf)
				} else {
					result, err = publicBearer.SignOut(ctx, r)
				}
				if err != nil || !result.SignedOut {
					t.Fatal("repeat logout did not preserve transport removal", err)
				}
				var transitions, audits, events int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, id)).Scan(&transitions, &audits, &events); err != nil || transitions != 1 || audits != 1 || events != 1 {
					t.Fatal("non-atomic logout effects", err)
				}
			})
		}
	}
}
