//go:build integration

package reference_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

// Restart actual composition against the original durable challenge. This is
// primary RecoverSignin, not TOTP completion recovery or another password attempt.
func proveReferenceUsernamePrimaryRecovery(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, worker deliverypg.WorkerConfig, challenge passwordhttp.SigninResponse, cookies []*http.Cookie, additionalWorkers ...deliverypg.WorkerConfig) {
	t.Helper()
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("username primary recovery graph restart failed", err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error("username recovery graph cleanup failed", err)
		}
	}()
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, append([]deliverypg.WorkerConfig{worker}, additionalWorkers...)...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil || features.Initialize(ctx) != nil {
		t.Fatal("username primary recovery graph initialization failed", err)
	}
	owner, err := features.UsernameSignin()
	if err != nil || challenge.Recovery == nil {
		t.Fatal("username primary recovery owner or original correlation missing", err)
	}
	q := challenge.Recovery
	query := identity.RecoveryQuery{TenantID: q.TenantID, CommandID: q.CommandID, AnonymousFlowID: string(q.FlowID), ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: "identity.username.signin"}
	recovery, err := password.NewSigninRecovery(query, q.FlowID)
	if err != nil || q.CommandID != challenge.CommandID || q.ActorID != c.HTTPUsername.ActorID || q.ActorKind != authorization.SubjectServiceAccount {
		t.Fatal("username challenge recovery changed original primary correlation")
	}
	var flowCookie, deviceCookie string
	for _, cookie := range cookies {
		switch cookie.Name {
		case "__Host-identity_flow":
			flowCookie = cookie.Value
		case "__Host-identity_device":
			deviceCookie = cookie.Value
		}
	}
	codec, err := session.NewBrowserDeviceCodec(*c.HTTPPreAuth.Device)
	if err != nil {
		t.Fatal(err)
	}
	origin := c.PasswordSignin.PreAuth.Origin
	device, err := codec.Resolve(ctx, time.Now(), q.TenantID, origin, deviceCookie)
	if err != nil || flowCookie == "" {
		t.Fatal("username primary recovery lost original browser custody")
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(q.TenantID), Subject: authorization.Subject{Kind: q.ActorKind, ID: authorization.SubjectID(q.ActorID)}, Action: "identity.username.signin", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(q.FlowID)}}}
	request := password.SigninRecoveryRequest{Recovery: recovery, Cookie: auth.NewBearerCredential(flowCookie), Caller: caller, Origin: origin, Network: "127.0.0.1", Device: device.DeviceID()}
	expires, err := time.Parse(time.RFC3339, challenge.ChallengeExpiresAt)
	if err != nil {
		t.Fatal("original username challenge expiry missing")
	}
	history, err := owner.RecoverSignin(ctx, request)
	if err != nil || history.Validate() != nil || history.State != auth.SignInStateChallengeRequired || history.Issuance.CommandID != q.CommandID || !history.Issuance.Replayed || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || history.Challenge.ID != challenge.ChallengeID || !history.Challenge.ExpiresAt.Equal(expires) || history.Challenge.Proof != (capability.Proof{}) || history.SessionID != "" || history.Issuance.Token != (session.Token{}) || history.Issuance.Cookie.Name != "" || history.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("restarted username primary recovery changed metadata or redelivered credentials", err)
	}
	retained, _, err := history.Recovery.Bindings()
	if err != nil || retained != query {
		t.Fatal("username primary recovery retagged original operation or command")
	}
	request.Cookie = auth.NewBearerCredential(strings.Repeat("A", 43))
	if denied, err := owner.RecoverSignin(ctx, request); err == nil || denied.Challenge != (password.MFAChallengeResult{}) || denied.Issuance.Token != (session.Token{}) || denied.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("foreign browser obtained username primary challenge history")
	}
}
