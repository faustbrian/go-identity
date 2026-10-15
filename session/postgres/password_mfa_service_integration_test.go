//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// Seed a stored password-origin record using the existing owned session/factor
// fixture. This proves public native reads/current authority, not comparison,
// challenge creation or completed public password login.
func testPasswordMFASessionRead(t *testing.T, ctx context.Context, pool *database.Pool, repository Config, p MagicLinkAdmissionConfig, validation session.ServiceConfig, original session.Session, request session.GetRequest) {
	t.Helper()
	s, _ := original.Bindings()
	m, _ := original.MFAAuthentication().Bindings()
	primary, _ := original.MagicLinkAuthentication().Bindings()
	credentialID := "password-mfa-reader-fixture-" + m.Method
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,1,'identity/password',1,true)`, string(s.TenantID), string(s.UserID), credentialID); err != nil {
		t.Fatal(err)
	}
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 1, CredentialID: credentialID, CredentialVersion: 1, Proof: auth.Proof{ID: auth.ProofID(m.PrimaryCommandID), Tenant: string(s.TenantID), Subject: string(s.UserID), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: session.PasswordMFAPrimaryPurpose, Audience: s.Audience, IssuedAt: primary.AuthenticatedAt, ExpiresAt: primary.ValidUntil}}
	record, err := session.NewSessionWithPasswordMFA(s, original.MFAAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3 WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID, payload); err != nil {
		t.Fatal(err)
	}
	defer func() {
		wire, _, err := encodeRecord(original)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3 WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID, wire); err != nil {
			t.Error(err)
		}
	}()
	for _, corrupt := range []func(map[string]any){
		func(v map[string]any) { delete(v, "MFA") },
		func(v map[string]any) { v["MagicLink"] = map[string]any{} },
		func(v map[string]any) {
			v["Authentication"].(map[string]any)["Proof"].(map[string]any)["Purpose"] = "session-issue"
		},
		func(v map[string]any) { v["Authentication"].(map[string]any)["CredentialID"] = "" },
		func(v map[string]any) { v["MFA"].(map[string]any)["PrimaryCommandID"] = "AgICAgICAgICAgICAgICAg" },
		func(v map[string]any) { v["Schema"] = 12 },
	} {
		var fields map[string]any
		if err := json.Unmarshal(payload, &fields); err != nil {
			t.Fatal(err)
		}
		corrupt(fields)
		malformed, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3 WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID, malformed)
		var rejected *pgconn.PgError
		if !errors.As(err, &rejected) || rejected.Code != "23514" {
			t.Fatal("malformed password MFA storage admitted", err)
		}
	}
	csrf, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, KeyVersion: 7, Digest: [32]byte{9}})
	if err != nil {
		t.Fatal(err)
	}
	withCSRF, err := session.NewSessionWithPasswordMFAAndCSRF(s, original.MFAAuthentication(), csrf)
	if err != nil {
		t.Fatal(err)
	}
	csrfPayload, _, err := encodeRecord(withCSRF)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$3 WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID, csrfPayload); err != nil {
		t.Fatal("complete password MFA CSRF schema rejected", err)
	}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: p.GlobalAuthorityID, PolicyNamespace: p.PolicyNamespace, Audience: p.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	c := SessionServiceConfig{Repository: repository, Profile: profile, Validation: validation}
	service, err := NewMFAPasswordSessionService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Get(ctx, request)
	if err != nil || !result.Authenticated || result.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
		t.Fatal("native password MFA read denied", err)
	}
	if !result.ValidUntil().Equal(validation.Clock.Now().Add(20*time.Second - validation.ClockUncertainty)) {
		t.Fatal("password factor read renewed authority freshness")
	}
	combined, err := NewSelectedSessionService(pool, SelectedSessionServiceConfig{Repository: repository, Validation: validation, Admission: SelectedSessionAdmissionConfig{SingleFactor: SingleFactorSessionAdmissionConfig{Verified: &profile}, MFAPassword: &profile}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := combined.Get(ctx, request)
	if err != nil || !selected.Authenticated || selected.Session.MFAAuthentication() == (session.MFAAuthentication{}) || !selected.ValidUntil().Equal(result.ValidUntil()) {
		t.Fatal("combined password reader lost factor or renewed freshness", err)
	}
	ordinary, err := NewSessionService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if weaker, err := ordinary.Get(ctx, request); err != nil || weaker.Authenticated {
		t.Fatal("password MFA entered single-factor reader", err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(s.TenantID), string(s.UserID), credentialID); err != nil {
		t.Fatal(err)
	}
	if denied, err := service.Get(ctx, request); err != nil || denied.Authenticated {
		t.Fatal("disabled password credential still authenticates MFA session", err)
	}
	if denied, err := combined.Get(ctx, request); err != nil || denied.Authenticated {
		t.Fatal("combined reader fell back after credential denial", err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=true WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(s.TenantID), string(s.UserID), credentialID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=$3::numeric WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID), strconv.FormatUint(m.FactorAuthorityVersion, 10)); err != nil {
			t.Error(err)
		}
	}()
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(s.TenantID), string(s.UserID)); err != nil {
		t.Fatal(err)
	}
	if denied, err := service.Get(ctx, request); err != nil || denied.Authenticated {
		t.Fatal("changed factor generation still authenticates password MFA", err)
	}
	if denied, err := combined.Get(ctx, request); err != nil || denied.Authenticated {
		t.Fatal("combined reader fell back after factor denial", err)
	}
}
