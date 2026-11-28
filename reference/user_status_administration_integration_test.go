//go:build integration

package reference_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresAuthenticatedKeyedUserBanUnban(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, userStatusAdministration: true,
	}, true)
}

// Only the genuine administrator and the selected target are authorized. The
// ordinary registration/enrollment policy remains unchanged for other actions.
type referenceUserStatusAdministrationPolicy struct {
	actor, target identity.UserID
}

func (p *referenceUserStatusAdministrationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	request := c.Request
	if request.Action != "identity.admin.user-ban" && request.Action != "identity.admin.user-unban" {
		return (referenceRegistrationPolicy{}).Decide(ctx, c)
	}
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision != 9 || request.Tenant != otpTenant || request.Subject.Kind != authorization.SubjectUser || p.actor == "" || string(request.Subject.ID) != string(p.actor) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
	}
	if request.Resource.Type == "identity.user" && string(request.Resource.ID) == string(p.target) || request.Resource.Type == "identity.request-admission" && string(request.Resource.ID) == string(request.Action) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
}

func configureReferenceUserStatusAdministration(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	contracts := make(map[string]kernel.StatusConsumerContract)
	for _, owner := range []string{"identity/session", "identity/session/valkey", "identity/impersonation", "identity/apikey", "identity/apikey/valkey", "oauth-server", "oauth-server/device", "oauth-server/oidc", "authorization", "authorization/valkey", "identity/risk", "audit"} {
		contracts[owner] = kernel.StatusConsumerContract{Version: 1, Fingerprint: [32]byte{1}}
	}
	c.UserStatusAdministration = &reference.UserStatusAdministrationConfiguration{
		Status: identity.UserStatusConfig{
			Query: identity.UserQueryConfig{
				Clock: clock.System{}, MaximumDuration: time.Second, PolicyID: "reference-user-status", PolicyVersion: 9,
				RedactionReasons: []identity.PolicyReason{"visible"},
				ValidateCanonicalUserID: func(ctx context.Context, user identity.UserID) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					_, err := identity.ParseSubjectID(string(user))
					return err
				},
			},
			Policy: identity.StatusPolicy{
				MaximumSuspension: time.Hour, BanRequiresReason: true,
				AllowedTransitions: []identity.StatusTransition{
					{From: identity.StatusActive, To: identity.StatusBanned},
					{From: identity.StatusBanned, To: identity.StatusActive},
				},
			},
			PolicyVersion: 1, Reasons: []string{"security", "reviewed"},
		},
		Redact: func(ctx context.Context, input identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{VisibleFields: input.Fields, PolicyID: "reference-user-status", PolicyVersion: 9, Reason: "visible"}, ctx.Err()
		},
		RetentionPolicyVersion: 1, MaximumCascadeDuration: time.Hour, ConsumerContracts: contracts,
	}
}

func proveReferenceUserStatusAdministration(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, config reference.StoreConfiguration, policy *referenceUserStatusAdministrationPolicy, client *http.Client, base, origin string, messages <-chan string) {
	t.Helper()
	owner, err := features.UserStatusAdministration()
	if err != nil || owner == nil {
		t.Fatal("selected authenticated user status owner unavailable", err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	transport := *client
	transport.Jar = nil
	actorCookies, actorCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "status-administrator")
	actor := organizationHumanFromSession(t, ctx, sessions, actorCookies, actorCSRF)
	otherCookies, otherCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "status-unauthorized")
	other := organizationHumanFromSession(t, ctx, sessions, otherCookies, otherCSRF)
	target := registerReferenceOrganizationHuman(t, ctx, &transport, base, origin, features, workers, messages, "status-target")
	if actor.user == other.user || actor.user == target.user || other.user == target.user {
		t.Fatal("status acceptance requires independent genuine identities")
	}
	policy.actor, policy.target = actor.user, target.user
	actorSynchronizer, err := session.ParseCSRFToken(actorCSRF)
	if err != nil {
		t.Fatal(err)
	}
	otherSynchronizer, err := session.ParseCSRFToken(otherCSRF)
	if err != nil {
		t.Fatal(err)
	}
	key := func(value string) identity.IdempotencyKey {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	readTarget := func() (identity.Status, uint64, uint64) {
		t.Helper()
		var status identity.Status
		var version, authority string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT status,version::text,authority_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(target.user)).Scan(&status, &version, &authority); err != nil {
			t.Fatal("target authoritative status unavailable", err)
		}
		versionNumber, versionErr := strconv.ParseUint(version, 10, 64)
		authorityNumber, authorityErr := strconv.ParseUint(authority, 10, 64)
		if versionErr != nil || authorityErr != nil {
			t.Fatal("target stored invalid unsigned versions")
		}
		return status, versionNumber, authorityNumber
	}
	effects := func() [4]int {
		t.Helper()
		var result [4]int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings),(SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose IN ('identity.admin.user-ban','identity.admin.user-unban')),(SELECT count(*) FROM identity.status_cascades WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM identity.status_consumers c JOIN identity.status_cascades s USING(tenant_id,cascade_id) WHERE s.tenant_id=$1 AND s.user_id=$2)`, otpTenant, string(target.user)).Scan(&result[0], &result[1], &result[2], &result[3]); err != nil {
			t.Fatal("status effect snapshot unavailable", err)
		}
		return result
	}
	targetToken, err := session.ParseToken(target.cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	targetCredential, err := session.NewCredential(session.CredentialCookie, targetToken)
	if err != nil {
		t.Fatal(err)
	}
	assertOldSession := func(want bool) {
		t.Helper()
		observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: targetCredential})
		if err != nil || observed.Authenticated != want {
			t.Fatal("target original session authority differs from lifecycle", err)
		}
	}
	status, version, authority := readTarget()
	if status != identity.StatusActive {
		t.Fatal("genuine target did not begin active")
	}
	assertOldSession(true)
	ban := reference.AdminUserStatusRequest{
		TenantID: otpTenant, Bearer: auth.NewBearerCredential(actorCookies[0].Value), CSRF: actorSynchronizer,
		Key: key("reference-status-ban"), UserID: target.user, ExpectedVersion: version, ExpectedAuthorityVersion: authority, Reason: "security",
	}
	baseline := effects()
	denied := ban
	denied.Key, denied.CSRF = key("reference-status-wrong-csrf"), otherSynchronizer
	if result, err := owner.AdminUserBan(ctx, denied); err == nil || result.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("wrong CSRF admitted user ban")
	}
	denied = ban
	denied.Key, denied.Bearer, denied.CSRF = key("reference-status-unauthorized"), auth.NewBearerCredential(otherCookies[0].Value), otherSynchronizer
	if result, err := owner.AdminUserBan(ctx, denied); err == nil || result.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("genuine but unauthorized MFA actor admitted user ban")
	}
	if effects() != baseline {
		t.Fatal("authentication or authorization denial reserved a key or changed status effects")
	}
	if current, userVersion, securityVersion := readTarget(); current != status || userVersion != version || securityVersion != authority {
		t.Fatal("denied ban changed target authority")
	}
	assertOldSession(true)
	committed, err := owner.AdminUserBan(ctx, ban)
	if err != nil || committed.CommitOutcome != identity.CommitOutcomeCommitted || committed.CommandID == "" || committed.User.ID != target.user || committed.User.Status != identity.StatusBanned || committed.User.Version != version+1 || committed.Revocation.Status != identity.RevocationPending || committed.Revocation.AuthorityVersion != authority+1 || len(committed.Revocation.Owners) != 12 {
		t.Fatal("authenticated keyed ban did not commit the exact target transition", err)
	}
	if current, userVersion, securityVersion := readTarget(); current != identity.StatusBanned || userVersion != version+1 || securityVersion != authority+1 {
		t.Fatal("ban did not advance both authoritative target versions once")
	}
	assertOldSession(false)
	afterBan := effects()
	if afterBan != [4]int{baseline[0] + 1, baseline[1] + 1, baseline[2] + 1, baseline[3] + 12} {
		t.Fatal("ban did not atomically persist one key, command and pending consumer cascade")
	}
	replayed, err := owner.AdminUserBan(ctx, ban)
	if err != nil || !reflect.DeepEqual(replayed, committed) || effects() != afterBan {
		t.Fatal("same ban key did not return the exact original receipt without effects", err)
	}
	changed := ban
	changed.Reason = "reviewed"
	var conflict identity.ConflictError
	if result, err := owner.AdminUserBan(ctx, changed); !errors.As(err, &conflict) || result.CommitOutcome == identity.CommitOutcomeCommitted || effects() != afterBan {
		t.Fatal("same ban key with changed intent did not conflict without effects")
	}
	signedWhileBanned, _ := referencePasswordLogin(t, ctx, f, &transport, base, origin, nil, config.PasswordSignin.Native, "synthetic-registration-password", "status-target@example.invalid")
	if signedWhileBanned.SignedIn {
		t.Fatal("banned target acquired new authentication authority")
	}
	unban := ban
	unban.Key, unban.ExpectedVersion, unban.ExpectedAuthorityVersion = key("reference-status-unban"), version+1, authority+1
	unban.Reason = ""
	restored, err := owner.AdminUserUnban(ctx, unban)
	if err != nil || restored.CommitOutcome != identity.CommitOutcomeCommitted || restored.CommandID == committed.CommandID || restored.User.ID != target.user || restored.User.Status != identity.StatusActive || restored.User.Version != version+2 || restored.Revocation.Status != identity.RevocationPending || restored.Revocation.AuthorityVersion != authority+2 || len(restored.Revocation.Owners) != 9 {
		t.Fatal("authenticated keyed unban did not commit new active authority", err)
	}
	if current, userVersion, securityVersion := readTarget(); current != identity.StatusActive || userVersion != version+2 || securityVersion != authority+2 {
		t.Fatal("unban did not advance both authoritative target versions once")
	}
	assertOldSession(false)
	afterUnban := effects()
	if afterUnban != [4]int{afterBan[0] + 1, afterBan[1] + 1, afterBan[2] + 1, afterBan[3] + 9} {
		t.Fatal("unban did not persist its own key, command and pending consumer cascade")
	}
	replayed, err = owner.AdminUserUnban(ctx, unban)
	if err != nil || !reflect.DeepEqual(replayed, restored) || effects() != afterUnban {
		t.Fatal("same unban key did not return the exact original receipt without effects", err)
	}
	fresh, token := referencePasswordLogin(t, ctx, f, &transport, base, origin, nil, config.PasswordSignin.Native, "synthetic-registration-password", "status-target@example.invalid")
	if !fresh.SignedIn || fresh.SessionID == target.sessionID || token == targetToken {
		t.Fatal("unbanned target could not obtain a distinct genuine password session")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !observed.Authenticated || observed.ValidateAt(time.Now()) != nil {
		t.Fatal("fresh post-unban session is not current for the original target", err)
	}
	binding, err := observed.Session.Bindings()
	if err != nil || binding.UserID != target.user {
		t.Fatal("fresh post-unban session changed target identity", err)
	}
	assertOldSession(false)
}
