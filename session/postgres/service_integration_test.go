//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// The surrounding test owns the isolated database and full migration history.
// Fixtures seed primary rows, not a substitute SessionReader or domain store.
func testNativeSessionAuthentication(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('session-read',1,true);
 INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('session-read','reader','active',1);
 INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('session-read','reader','password',1,'identity/password',1,true)`); err != nil {
		t.Fatal(err)
	}
	scope := authority.AuthorityScope{TenantID: "session-read", PolicyNamespace: "users", SubjectID: "reader"}
	if _, err := authority.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.NewDigestKey(2, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := testSession(t).Bindings()
	spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID, spec.Version, spec.FamilyVersion = "session-read", "reader", "read-family", "read-session", 1, 1
	spec.IssuedAt, spec.LastActivityAt = now, now
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "session-read", Subject: "reader", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "service-a", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}
	spec.Lookup, err = token.Digest(key, "session-read")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: spec.TenantID}, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	bind := func(s *session.SessionSpec) {
		t.Helper()
		sk, e := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
		if e != nil {
			t.Fatal(e)
		}
		pk, e := scope.Key()
		if e != nil {
			t.Fatal(e)
		}
		b := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
		s.Authority, e = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b(keys.Global), Tenant: b(keys.Tenant), User: b(keys.User), Identifier: b(keys.Identifier), Credential: b(keys.Credential), SessionFamily: b(sk.Family), Session: b(sk.Session), Authorization: b(pk)})
		if e != nil {
			t.Fatal(e)
		}
	}
	bind(&spec)
	insert := func(s session.SessionSpec) {
		t.Helper()
		record, e := session.NewSession(s)
		if e != nil {
			t.Fatal(e)
		}
		payload, expiry, e := encodeRecord(record)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(s.TenantID), s.FamilyID, string(s.UserID), now.UTC().Format(storedTimeLayout)); e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8)`, string(s.TenantID), s.SessionID, string(s.UserID), s.FamilyID, int64(s.Lookup.KeyVersion), s.Lookup.Sum[:], expiry, payload); e != nil {
			t.Fatal(e)
		}
	}
	insert(spec)
	config := SessionServiceConfig{Repository: Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: issueTestClock{now: now}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key, second}}}
	service, err := NewSessionService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	request := session.GetRequest{TenantID: "session-read", Credential: credential}
	for _, change := range []func(*SessionServiceConfig){
		func(c *SessionServiceConfig) { c.Repository.MaximumDuration = 2 * time.Second },
		func(c *SessionServiceConfig) { c.Profile.Audience = "wrong" },
		func(c *SessionServiceConfig) { c.Profile.CredentialKind = identity.CredentialPasskey },
		func(c *SessionServiceConfig) { c.Validation.Profile = session.StorageSecondary },
		func(c *SessionServiceConfig) { c.Validation.Clock = nil },
		func(c *SessionServiceConfig) { c.Validation.LookupKeys = nil },
	} {
		copied := config
		change(&copied)
		if got, e := NewSessionService(pool, copied); e == nil || got != nil {
			t.Fatal("invalid native composition accepted")
		}
	}
	positive, err := service.Get(ctx, request)
	if err != nil || !positive.Authenticated || positive.ValidateAt(now) != nil || !positive.ValidUntil().Equal(now.Add(20*time.Second-time.Millisecond)) {
		t.Fatal("native primary authority denied", err)
	}
	selected, err := NewSelectedSessionService(pool, SelectedSessionServiceConfig{
		Repository: config.Repository, Validation: config.Validation,
		Admission: SelectedSessionAdmissionConfig{
			SingleFactor: SingleFactorSessionAdmissionConfig{Verified: &profile},
			Passkey: &PasskeySessionAdmission{
				Profile:   PasskeyAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, RPNamespace: "rp-a"},
				Authority: &passkeyTestAuthority{},
			},
		},
	})
	if err != nil {
		t.Fatal("combined password/passkey reader", err)
	}
	if got, err := selected.Get(ctx, request); err != nil || !got.Authenticated || !got.ValidUntil().Equal(positive.ValidUntil()) {
		t.Fatal("selecting passkeys changed password authority or freshness", err)
	}
	for _, dimension := range []string{"organization", "factor", "passkey", "scope"} {
		changed := spec
		a, _ := changed.Authority.Bindings()
		optional := session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: dimension, Version: 1}}
		switch dimension {
		case "organization":
			a.ActiveOrganizationID, a.Organization = "org", optional
		case "factor":
			a.Factor = optional
		case "passkey":
			a.Passkey = optional
		case "scope":
			a.Identifier.ScopeKey = "foreign-key"
		}
		changed.Authority, err = session.NewAuthoritySnapshot(a)
		if err != nil {
			t.Fatal(err)
		}
		record, e := session.NewSession(changed)
		if e != nil {
			t.Fatal(e)
		}
		payload, _, e := encodeRecord(record)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1 WHERE tenant_id='session-read'`, payload); e != nil {
			t.Fatal(e)
		}
		if got, e := service.Get(ctx, request); e != nil || got.Authenticated {
			t.Fatal("unsupported or foreign authority admitted", e)
		}
		if got, e := selected.Get(ctx, request); e != nil || got.Authenticated {
			t.Fatal("passkey selection admitted unsupported or foreign password authority", e)
		}
	}
	original, _ := session.NewSession(spec)
	payload, _, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1 WHERE tenant_id='session-read'`, payload); err != nil {
		t.Fatal(err)
	}
	// Four trusted samples: core call start, native read start, native finish,
	// core finish. A delayed response must retain the original source window.
	delayedConfig := config
	calls := 0
	delayedConfig.Validation.Clock = sessionReadClock(func() time.Time {
		calls++
		if calls > 2 {
			return now.Add(4 * time.Second)
		}
		return now
	})
	delayed, err := NewSessionService(pool, delayedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got, e := delayed.Get(ctx, request); e != nil || !got.Authenticated || !got.ValidUntil().Equal(positive.ValidUntil()) {
		t.Fatal("delayed primary renewed evidence", e)
	}
	for _, sql := range []string{
		`UPDATE identity.global_authorities SET version=2 WHERE authority_id='deployment-issue'`,
		`UPDATE identity.tenant_authorities SET version=2 WHERE tenant_id='session-read'`,
		`UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id='session-read'`,
		`UPDATE identity.users SET authority_version=2 WHERE tenant_id='session-read'`,
		`UPDATE identity.users SET identifier_version=2 WHERE tenant_id='session-read'`,
		`UPDATE identity.users SET credential_version=2 WHERE tenant_id='session-read'`,
		`UPDATE identity.users SET status='banned' WHERE tenant_id='session-read'`,
		`UPDATE identity.credential_references SET version=2 WHERE tenant_id='session-read'`,
		`UPDATE identity.credential_references SET enabled=false WHERE tenant_id='session-read'`,
		`UPDATE identity.credential_references SET kind=2,owner='passkey' WHERE tenant_id='session-read'`,
		`UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id='session-read'`,
		`UPDATE session_store.families SET version=2 WHERE tenant_id='session-read'`,
		`UPDATE session_store.families SET state='revoked' WHERE tenant_id='session-read'`,
		`UPDATE session_store.sessions SET state='revoked' WHERE tenant_id='session-read'`,
	} {
		if _, err = pool.Raw().Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
		if got, e := service.Get(ctx, request); e != nil || got.Authenticated || got.Session != (session.Session{}) {
			t.Fatal("changed primary authority admitted", e)
		}
		if got, e := selected.Get(ctx, request); e != nil || got.Authenticated || got.Session != (session.Session{}) {
			t.Fatal("passkey selection bypassed current password authority", e)
		}
		// Fixture restoration only; product lifecycle never resets security epochs.
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity.global_authorities SET version=1 WHERE authority_id='deployment-issue'; UPDATE identity.tenant_authorities SET version=1,enabled=true WHERE tenant_id='session-read'; UPDATE identity.users SET authority_version=1,identifier_version=1,credential_version=1,status='active' WHERE tenant_id='session-read'; UPDATE identity.credential_references SET version=1,enabled=true,kind=1,owner='identity/password' WHERE tenant_id='session-read'; UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id='session-read'; UPDATE session_store.families SET version=1,state='active' WHERE tenant_id='session-read'; UPDATE session_store.sessions SET state='active' WHERE tenant_id='session-read'`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET version=42 WHERE tenant_id='session-read'`); err != nil {
		t.Fatal(err)
	}
	if got, e := service.Get(ctx, request); e != nil || !got.Authenticated {
		t.Fatal("aggregate CAS substituted for authority", e)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=$1 WHERE tenant_id='session-read'`, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, e := service.Get(ctx, request); e != nil || !got.Authenticated || !got.ValidUntil().Equal(now.Add(5*time.Second-time.Millisecond)) {
		t.Fatal("credential expiry did not cap original validity", e)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=$1 WHERE tenant_id='session-read'`, now); err != nil {
		t.Fatal(err)
	}
	if got, e := service.Get(ctx, request); e != nil || got.Authenticated {
		t.Fatal("exclusive credential expiry accepted", e)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET expires_at=NULL WHERE tenant_id='session-read'`); err != nil {
		t.Fatal(err)
	}
	foreign := request
	foreign.TenantID = "issue"
	if got, e := service.Get(ctx, foreign); e != nil || got.Authenticated {
		t.Fatal("foreign tenant accepted", e)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	var cancellation identity.CancelledError
	if got, e := service.Get(cancelled, request); !errors.As(e, &cancellation) || got.Authenticated {
		t.Fatal("cancellation admitted", e)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, e := service.Get(ctx, request); e != nil || !got.Authenticated {
				t.Error("concurrent native reader", e)
			}
		}()
	}
	wg.Wait()
	// Two retained key versions identifying different rows must never pick one.
	other := spec
	other.SessionID, other.FamilyID = "other-session", "other-family"
	other.Lookup, err = token.Digest(second, "session-read")
	if err != nil {
		t.Fatal(err)
	}
	bind(&other)
	insert(other)
	if got, e := service.Get(ctx, request); e != nil || got.Authenticated {
		t.Fatal("ambiguous retained-key lookup admitted", e)
	}
	if _, err = pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id='session-read' AND session_id='other-session'; ALTER TABLE identity.credential_references RENAME TO missing_session_reader_credentials`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, e := pool.Raw().Exec(ctx, `ALTER TABLE identity.missing_session_reader_credentials RENAME TO credential_references`); e != nil {
			t.Error("restore fixture table", e)
		}
	}()
	if got, e := service.Get(ctx, request); !errors.Is(e, session.ErrUnavailable) || got.Authenticated {
		t.Fatal("missing primary infrastructure accepted", e)
	}
	if positive.ValidateAt(positive.ValidUntil()) == nil {
		t.Fatal("old evidence outlived outage deadline")
	}
}
