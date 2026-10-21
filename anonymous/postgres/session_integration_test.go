//go:build integration

package anonymouspostgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

type anonymousReadClock func() time.Time

func (c anonymousReadClock) Now() time.Time { return c() }

// This reader consumes the actual preceding kernel/lifecycle/session creation;
// no application store or synthesized SessionObservation supplies admission.
func testAnonymousSessionRecognition(t *testing.T, ctx context.Context, pool *database.Pool, subject anonymous.SubjectSpec, token session.Token, key session.DigestKey) {
	t.Helper()
	now := subject.CreatedAt
	c := anonymouspg.SessionServiceConfig{
		Repository: anonymouspg.Config{Schema: "anonymous_store", MaximumDuration: time.Second},
		Sessions:   sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second},
		Profile:    sessionpg.AnonymousAdmissionConfig{GlobalAuthorityID: "anonymous-deployment", PolicyNamespace: "guests", Audience: "service-a"},
		Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: anonymousReadClock(func() time.Time { return now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}},
	}
	service, err := anonymouspg.NewSessionService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	request := session.GetRequest{TenantID: subject.TenantID, Credential: credential}
	positive, err := service.Get(ctx, request)
	if err != nil || !positive.Recognized || positive.ValidateAt(now) != nil || !positive.ValidUntil().Equal(now.Add(20*time.Second-time.Millisecond)) {
		t.Fatal("native anonymous session not recognized", err)
	}
	if positive.ValidateAt(positive.ValidUntil()) == nil {
		t.Fatal("original anonymous validity renewed at its exclusive boundary")
	}
	foreign := request
	foreign.TenantID = "tenant-b"
	if got, err := service.Get(ctx, foreign); err != nil || got.Recognized || got.Session != (session.Session{}) {
		t.Fatal("anonymous session crossed tenant", err)
	}
	// The legacy verified-user factory must stay closed even with a valid guest
	// token and valid primary guest lifecycle underneath it.
	legacy, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: c.Sessions, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: c.Profile.GlobalAuthorityID, PolicyNamespace: c.Profile.PolicyNamespace, Audience: c.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Validation: c.Validation})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := legacy.Get(ctx, request); err != nil || got.Authenticated {
		t.Fatal("anonymous session became verified-user authentication", err)
	}
	for _, check := range []struct{ name, change, restore string }{
		{"directory disabled", `UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id=$1`, `UPDATE identity.tenant_authorities SET enabled=true WHERE tenant_id=$1`},
		{"global epoch", `UPDATE identity.global_authorities SET version=2`, `UPDATE identity.global_authorities SET version=1`},
		{"user epoch", `UPDATE identity.users SET authority_version=2 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.users SET authority_version=1 WHERE tenant_id=$1 AND user_id=$2`},
		{"identifier epoch", `UPDATE identity.users SET identifier_version=2 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.users SET identifier_version=1 WHERE tenant_id=$1 AND user_id=$2`},
		{"credential epoch", `UPDATE identity.users SET credential_version=2 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.users SET credential_version=1 WHERE tenant_id=$1 AND user_id=$2`},
		{"account blocked", `UPDATE identity.users SET status='banned' WHERE tenant_id=$1 AND user_id=$2`, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`},
		{"anonymous terminal", `UPDATE anonymous_store.subjects SET state=2,version=2 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE anonymous_store.subjects SET state=1,version=1 WHERE tenant_id=$1 AND user_id=$2`},
		{"policy epoch", `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id=$1 AND subject_id=$2`, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id=$1 AND subject_id=$2`},
		{"family epoch", `UPDATE session_store.families SET version=2 WHERE tenant_id=$1 AND user_id=$2`, `UPDATE session_store.families SET version=1 WHERE tenant_id=$1 AND user_id=$2`},
		{"family revoked", `UPDATE session_store.families SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, `UPDATE session_store.families SET state='active' WHERE tenant_id=$1 AND user_id=$2`},
		{"session revoked", `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, `UPDATE session_store.sessions SET state='active' WHERE tenant_id=$1 AND user_id=$2`},
	} {
		t.Run(check.name, func(t *testing.T) {
			exec := func(query string) {
				t.Helper()
				// Supply only the actual statement's parameters. These are test-only
				// primary mutations; restoring an epoch is never a supported API.
				var args []any
				for _, marker := range []string{"$1", "$2"} {
					if strings.Contains(query, marker) {
						args = append(args, []string{string(subject.TenantID), string(subject.UserID)}[len(args)])
					}
				}
				if _, err := pool.Raw().Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(check.change)
			got, readErr := service.Get(ctx, request)
			exec(check.restore)
			if readErr != nil || got.Recognized || got.Session != (session.Session{}) {
				t.Fatal("changed primary authority admitted", readErr)
			}
			if got, err := service.Get(ctx, request); err != nil || !got.Recognized {
				t.Fatal("denial oracle lacked a live positive control", err)
			}
		})
	}
	calls := 0
	delayedConfig := c
	delayedConfig.Validation.Clock = anonymousReadClock(func() time.Time {
		calls++
		if calls > 2 {
			return now.Add(4 * time.Second)
		}
		return now
	})
	delayed, err := anonymouspg.NewSessionService(pool, delayedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := delayed.Get(ctx, request); err != nil || !got.Recognized || !got.ValidUntil().Equal(positive.ValidUntil()) {
		t.Fatal("later owner reads renewed anonymous validity", err)
	}
	for _, profile := range []string{"directory", "policy", "audience"} {
		selected := c
		switch profile {
		case "directory":
			selected.Profile.GlobalAuthorityID = "another-deployment"
		case "policy":
			selected.Profile.PolicyNamespace = "another-policy"
		case "audience":
			selected.Profile.Audience, selected.Validation.Audience = "another-audience", "another-audience"
		}
		other, err := anonymouspg.NewSessionService(pool, selected)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := other.Get(ctx, request); err != nil || got.Recognized {
			t.Fatal("equal epochs authenticated a foreign profile", profile, err)
		}
	}
	t.Run("absolute anonymous expiry caps evidence", func(t *testing.T) {
		expires := subject.CreatedAt.Add(15 * time.Minute)
		if _, err := pool.Raw().Exec(ctx, `UPDATE anonymous_store.subjects SET expires_at=$3 WHERE tenant_id=$1 AND user_id=$2`, string(subject.TenantID), string(subject.UserID), expires); err != nil {
			t.Fatal(err)
		}
		now = expires.Add(-2 * time.Second)
		got, readErr := service.Get(ctx, request)
		now = expires
		boundary, boundaryErr := service.Get(ctx, request)
		now = subject.CreatedAt
		if _, err := pool.Raw().Exec(ctx, `UPDATE anonymous_store.subjects SET expires_at=$3 WHERE tenant_id=$1 AND user_id=$2`, string(subject.TenantID), string(subject.UserID), subject.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		if readErr != nil || !got.Recognized || !got.ValidUntil().Equal(expires.Add(-time.Millisecond)) || got.ValidateAt(expires) == nil {
			t.Fatal("anonymous expiry was replaced by a newer evidence lease", readErr)
		}
		if boundaryErr != nil || boundary.Recognized {
			t.Fatal("absolute expiry was inclusive or renewable", boundaryErr)
		}
	})
	for _, delta := range []time.Duration{-time.Nanosecond, 20 * time.Second} {
		calls := 0
		changed := c
		changed.Validation.Clock = anonymousReadClock(func() time.Time {
			calls++
			if calls > 2 {
				return now.Add(delta)
			}
			return now
		})
		reader, err := anonymouspg.NewSessionService(pool, changed)
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := reader.Get(ctx, request)
		if got.Recognized || delta < 0 && !errors.Is(readErr, session.ErrUnavailable) || delta > 0 && readErr != nil {
			t.Fatal("invalid original read window admitted or misclassified", delta, readErr)
		}
	}
	// Unavailable owner infrastructure must fail, not silently authenticate from
	// the already readable session/kernel record or a previous positive result.
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE anonymous_store.subjects RENAME TO unavailable_subjects`); err != nil {
		t.Fatal(err)
	}
	got, readErr := service.Get(ctx, request)
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE anonymous_store.unavailable_subjects RENAME TO subjects`); err != nil {
		t.Fatal(err)
	}
	if got.Recognized || !errors.Is(readErr, session.ErrUnavailable) {
		t.Fatal("missing lifecycle authority used a fallback", readErr)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := service.Get(cancelled, request); !errors.Is(err, identity.CancelledError{}) {
		t.Fatal("anonymous reader lost cancellation classification", err)
	}
}
