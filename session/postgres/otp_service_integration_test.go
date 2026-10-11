//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// Real primary reader coverage, not proof of public Send/Signin or issuance.
// No persistent credential reference is created for this passwordless user.
func testNativeOTPSessionAuthentication(t *testing.T, ctx context.Context, pool *database.Pool) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	const identifier = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES('otp-read',1,true);
 INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('otp-read','reader','active',1);
 INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at)
 VALUES('otp-read','reader','01ARZ3NDEKTSV4RRFFQ69G5FAV','email','otp-reader@example.test',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	scope := authority.AuthorityScope{TenantID: "otp-read", PolicyNamespace: "users", SubjectID: "reader"}
	if _, err := authority.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialBearer, token)
	s, _ := testSession(t).Bindings()
	s.TenantID, s.UserID, s.SessionID, s.FamilyID = "otp-read", "reader", "otp-read-session", "otp-read-family"
	s.Version, s.FamilyVersion = 1, 1
	s.IssuedAt, s.LastActivityAt = now.Add(-2*time.Minute), now
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationOTP}
	s.Lookup, _ = token.Digest(key, "otp-read")
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment-issue", TenantID: s.TenantID}, s.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	pk, _ := scope.Key()
	b := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b(keys.Global), Tenant: b(keys.Tenant), User: b(keys.User), Identifier: b(keys.Identifier), Credential: b(keys.Credential), SessionFamily: b(sk.Family), Session: b(sk.Session), Authorization: b(pk)})
	if err != nil {
		t.Fatal(err)
	}
	// Original OTP expiry is already past, but the issued session remains live.
	metadata, err := session.NewOTPAuthentication(session.OTPAuthenticationSpec{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", SendCommandID: "AgICAgICAgICAgICAgICAg", ChallengeID: "challenge", AttemptID: "AwMDAwMDAwMDAwMDAwMDAw", IdentifierID: identifier, IdentifierKind: identity.IdentifierEmail, IdentifierVersion: 1, VerificationVersion: 1, AuthenticatedAt: now.Add(-3 * time.Minute), ValidUntil: now.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	original, err := session.NewSessionWithOTP(s, metadata)
	if err != nil {
		t.Fatal(err)
	}
	payload, expiry, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES('otp-read','otp-read-family','reader',1,'active',$1);
 `, s.IssuedAt.UTC().Format(storedTimeLayout)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES('otp-read','otp-read-session','reader','otp-read-family',1,1,'active',1,$1,$2,$3::jsonb)`, s.Lookup.Sum[:], expiry, payload); err != nil {
		t.Fatal(err)
	}
	c := OTPSessionServiceConfig{Repository: Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: OTPAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a"}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: issueTestClock{now: now}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}}
	request := session.GetRequest{TenantID: "otp-read", Credential: credential}
	read := func() session.GetResult {
		t.Helper()
		service, err := NewOTPSessionService(pool, c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Get(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	positive := read()
	if !positive.Authenticated || !positive.ValidUntil().Equal(now.Add(20*time.Second-time.Millisecond)) {
		t.Fatal("native OTP reader denied exact live session or renewed authority")
	}
	for _, change := range []struct{ name, update, restore string }{
		{"global", `UPDATE identity.global_authorities SET version=2 WHERE authority_id='deployment-issue'`, `UPDATE identity.global_authorities SET version=1 WHERE authority_id='deployment-issue'`},
		{"tenant", `UPDATE identity.tenant_authorities SET version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.tenant_authorities SET version=1 WHERE tenant_id='otp-read'`},
		{"user", `UPDATE identity.users SET authority_version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.users SET authority_version=1 WHERE tenant_id='otp-read'`},
		{"identifier-epoch", `UPDATE identity.users SET identifier_version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.users SET identifier_version=1 WHERE tenant_id='otp-read'`},
		{"credential-epoch-without-credential", `UPDATE identity.users SET credential_version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.users SET credential_version=1 WHERE tenant_id='otp-read'`},
		{"authorization", `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id='otp-read'`, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id='otp-read'`},
		{"family", `UPDATE session_store.families SET version=2 WHERE tenant_id='otp-read'`, `UPDATE session_store.families SET version=1 WHERE tenant_id='otp-read'`},
		{"revoked-session", `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id='otp-read'`, `UPDATE session_store.sessions SET state='active' WHERE tenant_id='otp-read'`},
		{"identifier-record", `UPDATE identity.identifiers SET version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.identifiers SET version=1 WHERE tenant_id='otp-read'`},
		{"verification-record", `UPDATE identity.identifiers SET verification_version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.identifiers SET verification_version=1 WHERE tenant_id='otp-read'`},
		{"unverified", `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id='otp-read'`, `UPDATE identity.identifiers SET verified=true,is_primary=true,verification_state=2,verified_at=clock_timestamp() WHERE tenant_id='otp-read'`},
		{"blocked", `UPDATE identity.users SET status='banned' WHERE tenant_id='otp-read'`, `UPDATE identity.users SET status='active' WHERE tenant_id='otp-read'`},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, change.update); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := pool.Raw().Exec(ctx, change.restore); err != nil {
					t.Fatal(err)
				}
			}()
			if read().Authenticated {
				t.Fatal("stale OTP session authenticated")
			}
		})
	}
	if !read().Authenticated {
		t.Fatal("restored isolated fixture failed")
	}
	t.Run("phone", func(t *testing.T) {
		const phoneID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('otp-read','reader','01ARZ3NDEKTSV4RRFFQ69G5FAW','phone','+358401234567',true,true,1,2,1,clock_timestamp())`); err != nil {
			t.Fatal(err)
		}
		p, _ := metadata.Bindings()
		p.IdentifierID, p.IdentifierKind = phoneID, identity.IdentifierPhone
		phone, err := session.NewOTPAuthentication(p)
		if err != nil {
			t.Fatal(err)
		}
		record, err := session.NewSessionWithOTP(s, phone)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _, err := encodeRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='otp-read'`, encoded); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='otp-read'`, payload); err != nil {
				t.Fatal(err)
			}
		}()
		if !read().Authenticated {
			t.Fatal("exact verified phone session denied")
		}
	})
	t.Run("original authority deadline", func(t *testing.T) {
		original := c.Validation.Clock
		defer func() { c.Validation.Clock = original }()
		for _, delay := range []time.Duration{4 * time.Second, 20 * time.Second} {
			calls := 0
			c.Validation.Clock = sessionReadClock(func() time.Time {
				calls++
				if calls > 2 {
					return now.Add(delay)
				}
				return now
			})
			got := read()
			if delay < 20*time.Second {
				if !got.Authenticated || !got.ValidUntil().Equal(positive.ValidUntil()) {
					t.Fatal("delayed response renewed original evidence")
				}
			} else if got.Authenticated {
				t.Fatal("expired original authority read authenticated")
			}
		}
	})
	t.Run("proof profile stays closed", func(t *testing.T) {
		legacy, err := NewSessionService(pool, SessionServiceConfig{Repository: c.Repository, Validation: c.Validation, Profile: IdentifierAdmissionConfig{GlobalAuthorityID: c.Profile.GlobalAuthorityID, PolicyNamespace: c.Profile.PolicyNamespace, Audience: c.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := legacy.Get(ctx, request); err != nil || got.Authenticated {
			t.Fatal("legacy profile implicitly admitted OTP", err)
		}
		foreign := request
		foreign.TenantID = "session-read"
		selected, err := NewOTPSessionService(pool, c)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := selected.Get(ctx, foreign); err != nil || got.Authenticated {
			t.Fatal("OTP reader crossed tenant", err)
		}
	})
	t.Run("magic-link profile", func(t *testing.T) {
		p, _ := metadata.Bindings()
		s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}
		m, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: p.CommandID, RequestCommandID: p.SendCommandID, CapabilityID: "original-grant", IdentifierID: p.IdentifierID, IdentifierVersion: p.IdentifierVersion, VerificationVersion: p.VerificationVersion, AuthenticatedAt: p.AuthenticatedAt, ValidUntil: p.ValidUntil})
		if err != nil {
			t.Fatal(err)
		}
		record, err := session.NewSessionWithMagicLink(s, m)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _, err := encodeRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='otp-read'`, encoded); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET record=$1::jsonb WHERE tenant_id='otp-read'`, payload); err != nil {
				t.Fatal(err)
			}
		}()
		service, err := NewMagicLinkSessionService(pool, MagicLinkSessionServiceConfig{Repository: c.Repository, Profile: MagicLinkAdmissionConfig(c.Profile), Validation: c.Validation})
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Get(ctx, request)
		if err != nil || !got.Authenticated || !got.ValidUntil().Equal(positive.ValidUntil()) {
			t.Fatal("magic-link reader denied exact live session", err)
		}
		if read().Authenticated {
			t.Fatal("OTP reader borrowed magic-link provenance")
		}
		keys, err := keyring.New(map[string][]byte{"cache": make([]byte, 32)})
		if err != nil {
			t.Fatal(err)
		}
		crypto, err := envelope.NewService(keys)
		if err != nil {
			t.Fatal(err)
		}
		cacheProfile := session.EncryptedCacheConfig{Issuer: "issuer", Environment: "test", DeploymentEpoch: 1, KeyReference: "cache", MaximumAge: time.Minute, MaximumBytes: 32768}
		codec, err := session.NewEncryptedCacheCodec(service, crypto, cacheProfile)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := codec.Seal(ctx, got)
		if err != nil {
			t.Fatal(err)
		}
		passwordReader, err := NewSessionService(pool, SessionServiceConfig{Repository: c.Repository, Validation: c.Validation, Profile: IdentifierAdmissionConfig{GlobalAuthorityID: c.Profile.GlobalAuthorityID, PolicyNamespace: c.Profile.PolicyNamespace, Audience: c.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}})
		if err != nil {
			t.Fatal(err)
		}
		otpReader, err := NewOTPSessionService(pool, c)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []*session.SessionService{otpReader, passwordReader} {
			cache, err := session.NewEncryptedCacheCodec(target, crypto, cacheProfile)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := cache.Get(ctx, request, blob); err != nil || got.Authenticated {
				t.Fatal("native foreign profile admitted magic-link warm cache", err)
			}
		}
		restarted, err := NewMagicLinkSessionService(pool, MagicLinkSessionServiceConfig{Repository: c.Repository, Profile: MagicLinkAdmissionConfig(c.Profile), Validation: c.Validation})
		if err != nil {
			t.Fatal(err)
		}
		warm, err := session.NewEncryptedCacheCodec(restarted, crypto, cacheProfile)
		if err != nil {
			t.Fatal(err)
		}
		if restored, err := warm.Get(ctx, request, blob); err != nil || !restored.Authenticated || !restored.ValidUntil().Equal(got.ValidUntil()) {
			t.Fatal("native same-profile restoration changed validity", err)
		}
		for _, change := range []func(*MagicLinkSessionServiceConfig){
			func(c *MagicLinkSessionServiceConfig) { c.Profile.GlobalAuthorityID = "different-deployment" },
			func(c *MagicLinkSessionServiceConfig) { c.Profile.PolicyNamespace = "different-policy" },
		} {
			other := MagicLinkSessionServiceConfig{Repository: c.Repository, Profile: MagicLinkAdmissionConfig(c.Profile), Validation: c.Validation}
			change(&other)
			target, err := NewMagicLinkSessionService(pool, other)
			if err != nil {
				t.Fatal(err)
			}
			cache, err := session.NewEncryptedCacheCodec(target, crypto, cacheProfile)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := cache.Get(ctx, request, blob); err != nil || got.Authenticated {
				t.Fatal("same method borrowed another authority profile", err)
			}
		}
		for _, change := range []struct{ name, update, restore string }{
			{"blocked", `UPDATE identity.users SET status='banned' WHERE tenant_id='otp-read'`, `UPDATE identity.users SET status='active' WHERE tenant_id='otp-read'`},
			{"credential-epoch", `UPDATE identity.users SET credential_version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.users SET credential_version=1 WHERE tenant_id='otp-read'`},
			{"verification", `UPDATE identity.identifiers SET verification_version=2 WHERE tenant_id='otp-read'`, `UPDATE identity.identifiers SET verification_version=1 WHERE tenant_id='otp-read'`},
			{"revoked", `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id='otp-read'`, `UPDATE session_store.sessions SET state='active' WHERE tenant_id='otp-read'`},
		} {
			t.Run(change.name, func(t *testing.T) {
				if _, err := pool.Raw().Exec(ctx, change.update); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, change.restore); err != nil {
						t.Fatal(err)
					}
				}()
				if got, err := service.Get(ctx, request); err != nil || got.Authenticated {
					t.Fatal("stale magic-link authority admitted", err)
				}
			})
		}
		foreign := request
		foreign.TenantID = "session-read"
		if got, err := service.Get(ctx, foreign); err != nil || got.Authenticated {
			t.Fatal("magic-link reader crossed tenant", err)
		}
	})
}
