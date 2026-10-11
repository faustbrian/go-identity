//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// This installs an explicit original password flow through its native owner.
// The selected HTTP initiation profile remains OTP-specific and is not relabeled
// as password custody. Login, counted risk and session issuance use the public
// graph port, not an application-written evaluator, domain store or transaction.
func referencePasswordLogin(t *testing.T, ctx context.Context, f liveStores, service password.SigninService, c passwordpg.SigninConfig, raw string) password.SigninResult {
	t.Helper()
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	flowID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	cookie := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{115}, 32))
	token, err := session.ParseToken(cookie)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: otpTenant, Action: "identity.password.signin", Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], Nonce: [32]byte{116}, Remember: remember, PolicyID: c.PolicyID, PolicyVersion: 9}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	digest, err := token.PreAuthDigest(c.FlowKeys[0], binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := sessionpg.InsertPreAuth(ctx, referenceOriginalFlowFixture{pool: f.pool}, c.Session, flow); err != nil {
		t.Fatal("native original password flow fixture", err)
	}
	secret, err := primitive.NewSecret([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}
	result, err := service.Signin(ctx, password.SigninRequest{TenantID: otpTenant, PreAuthID: flowID, Cookie: auth.NewBearerCredential(cookie), Identifier: "recipient@example.invalid", Password: secret, Remember: remember, Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], Caller: caller, Network: "127.0.0.1", Device: "reference-password-device"})
	if err != nil {
		t.Fatal("reference public password signin", err)
	}
	return result
}

type referenceOriginalFlowFixture struct{ pool *database.Pool }

func (f referenceOriginalFlowFixture) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return f.pool.Raw().Query(ctx, sql, args...)
}

func (f referenceOriginalFlowFixture) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := f.pool.Raw().Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}
