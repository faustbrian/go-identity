//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresAuthenticatedKeyedUserBanUnbanHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true,
		userStatusAdministration: true, userStatusHTTP: true,
	}, true)
}

func configureReferenceUserStatusHTTP(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	c.HTTPUserStatusAdministration = &reference.HTTPUserStatusAdministrationConfiguration{
		Ban: true, Unban: true, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)},
		AdminNamespace: "reference-user-status-admin", AdminKey: [32]byte{221},
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if event.Operation != "identity.admin.user-ban" && event.Operation != "identity.admin.user-unban" || event.Reason != "limited" && event.Reason != "unavailable" {
				t.Error("user status quota lost exact operation or redacted denial reason")
			}
			return ctx.Err()
		},
	}
}

type referenceUserStatusHTTPReceipt struct {
	CommandID     identity.CommandID `json:"commandID"`
	CommitOutcome string             `json:"commitOutcome"`
	User          struct {
		ID       identity.UserID   `json:"id"`
		TenantID identity.TenantID `json:"tenantID"`
		Status   identity.Status   `json:"status"`
		Version  uint64            `json:"version"`
	} `json:"user"`
	Revocation struct {
		CascadeID        identity.CascadeID `json:"cascadeID"`
		Generation       uint64             `json:"generation"`
		AuthorityVersion uint64             `json:"authorityVersion"`
		Status           string             `json:"status"`
		Owners           []struct {
			Owner  string `json:"owner"`
			Status string `json:"status"`
		} `json:"owners"`
		ExternalLimitations []string `json:"externalLimitations"`
	} `json:"revocation"`
}

func proveReferenceUserStatusHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, config reference.StoreConfiguration, policy *referenceUserStatusAdministrationPolicy, client *http.Client, base, origin string, messages <-chan string) {
	t.Helper()
	if !strings.HasPrefix(base, "https://") || config.HTTPUserStatusAdministration == nil || config.HTTPRate == nil || config.Impersonation != nil {
		t.Fatal("user status HTTPS acceptance requires standalone status and canonical rate selection")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	transport := *client
	transport.Jar = nil
	actorCookies, actorCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "status-http-administrator")
	actor := organizationHumanFromSession(t, ctx, sessions, actorCookies, actorCSRF)
	otherCookies, otherCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "status-http-unauthorized")
	other := organizationHumanFromSession(t, ctx, sessions, otherCookies, otherCSRF)
	target := registerReferenceOrganizationHuman(t, ctx, &transport, base, origin, features, workers, messages, "status-http-target")
	if actor.user == other.user || actor.user == target.user || other.user == target.user {
		t.Fatal("status HTTPS actors and target must be independent genuine identities")
	}
	policy.actor, policy.target = actor.user, target.user
	invoke := func(path string, body any, cookies []*http.Cookie, csrf, key string) (int, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", csrf)
		request.Header.Set("Idempotency-Key", key)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("status HTTPS transport unavailable", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("status HTTPS response violated bounded metadata-only custody")
		}
		for _, secret := range []string{actorCookies[0].Value, actorCSRF, otherCookies[0].Value, otherCSRF, target.cookies[0].Value, target.csrf, key} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("status HTTPS response disclosed original credential or request key")
			}
		}
		if response.StatusCode != http.StatusOK {
			var failure map[string]json.RawMessage
			if json.Unmarshal(data, &failure) != nil || failure["commitOutcome"] == nil || failure["error"] == nil || len(failure) < 2 || len(failure) > 3 || len(failure) == 3 && failure["commandID"] == nil {
				t.Fatal("status HTTPS failure returned fields outside its redacted outcome contract")
			}
		}
		return response.StatusCode, data
	}
	effects := func() [4]int64 {
		t.Helper()
		var state [4]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings),(SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND purpose IN ('identity.admin.user-ban','identity.admin.user-unban')),(SELECT count(*) FROM identity.status_cascades WHERE tenant_id=$1 AND user_id=$2),(SELECT count(*) FROM public.rate_limit_atomic_commands)`, otpTenant, string(target.user)).Scan(&state[0], &state[1], &state[2], &state[3]); err != nil {
			t.Fatal("status HTTPS native key, command, cascade or quota owner unavailable", err)
		}
		return state
	}
	var originalVersion, originalAuthority string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT version::text,authority_version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, otpTenant, string(target.user)).Scan(&originalVersion, &originalAuthority); err != nil {
		t.Fatal("genuine signed-in target is not active", err)
	}
	version, versionErr := strconv.ParseUint(originalVersion, 10, 64)
	authority, authorityErr := strconv.ParseUint(originalAuthority, 10, 64)
	if versionErr != nil || authorityErr != nil {
		t.Fatal("target status versions are not canonical unsigned integers")
	}
	oldToken, err := session.ParseToken(target.cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	oldCredential, err := session.NewCredential(session.CredentialCookie, oldToken)
	if err != nil {
		t.Fatal(err)
	}
	assertOldSession := func(authenticated bool) {
		t.Helper()
		current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: oldCredential})
		if err != nil || current.Authenticated != authenticated {
			t.Fatal("status HTTPS transition left incorrect original session authority", err)
		}
	}
	decode := func(data []byte, operation string, status identity.Status, version, authority uint64) referenceUserStatusHTTPReceipt {
		t.Helper()
		var receipt referenceUserStatusHTTPReceipt
		var metadata map[string]json.RawMessage
		if json.Unmarshal(data, &receipt) != nil || json.Unmarshal(data, &metadata) != nil || len(metadata) != 4 || receipt.CommandID == "" || receipt.CommitOutcome != "committed" || receipt.User.ID != target.user || receipt.User.TenantID != otpTenant || receipt.User.Status != status || receipt.User.Version != version || receipt.Revocation.Generation != 1 || receipt.Revocation.Status != "pending" || receipt.Revocation.AuthorityVersion != authority || len(receipt.Revocation.ExternalLimitations) != 0 {
			t.Fatal("status HTTPS lost exact safe user or pending native receipt metadata")
		}
		if _, err := identity.ParseCommandID(string(receipt.CommandID)); err != nil {
			t.Fatal("status HTTPS command identity is not canonical")
		}
		if _, err := identity.ParseCascadeID(string(receipt.Revocation.CascadeID)); err != nil {
			t.Fatal("status HTTPS cascade identity is not canonical")
		}
		var user, revocation map[string]json.RawMessage
		if json.Unmarshal(metadata["user"], &user) != nil || len(user) != 4 || json.Unmarshal(metadata["revocation"], &revocation) != nil || len(revocation) != 6 {
			t.Fatal("status HTTPS returned fields outside its safe metadata contract")
		}
		var ownerMetadata []map[string]json.RawMessage
		if json.Unmarshal(revocation["owners"], &ownerMetadata) != nil {
			t.Fatal("status HTTPS returned malformed consumer metadata")
		}
		for _, owner := range ownerMetadata {
			if len(owner) != 2 || owner["owner"] == nil || owner["status"] == nil {
				t.Fatal("status HTTPS returned fields outside safe consumer metadata")
			}
		}
		expectedOwners := (identity.UserStatusCommand{Binding: identity.CommandBinding{OperationID: operation}}).RequiredConsumers()
		owners := make([]string, len(receipt.Revocation.Owners))
		for i, owner := range receipt.Revocation.Owners {
			owners[i] = owner.Owner
			if owner.Status != "pending" {
				t.Fatal("status HTTPS claimed consumer cleanup completed")
			}
		}
		if !reflect.DeepEqual(owners, expectedOwners) {
			t.Fatal("status HTTPS omitted or reordered a required pending consumer")
		}
		return receipt
	}
	assertOldSession(true)
	banBody := map[string]any{"userID": target.user, "reason": "security"}
	before := effects()
	status, _ := invoke("/v1/admin/user-ban", banBody, actorCookies, otherCSRF, "status-http-wrong-csrf")
	if status != http.StatusForbidden || effects() != before {
		t.Fatal("wrong-CSRF ban reserved a key, changed authority or charged quota", status)
	}
	status, _ = invoke("/v1/admin/user-ban", banBody, otherCookies, otherCSRF, "status-http-unauthorized")
	if status != http.StatusForbidden || effects() != before {
		t.Fatal("unauthorized genuine MFA actor reserved a key, changed authority or charged quota", status)
	}
	status, banWire := invoke("/v1/admin/user-ban", banBody, actorCookies, actorCSRF, "status-http-ban")
	if status != http.StatusOK {
		t.Fatal("genuine administrator could not ban over HTTPS", status)
	}
	ban := decode(banWire, "identity.admin.user-ban", identity.StatusBanned, version+1, authority+1)
	assertOldSession(false)
	afterBan := effects()
	if afterBan != [4]int64{before[0] + 1, before[1] + 1, before[2] + 1, before[3] + 1} {
		t.Fatal("admitted HTTPS ban did not persist one native operation and charge quota exactly once")
	}
	status, replay := invoke("/v1/admin/user-ban", banBody, actorCookies, actorCSRF, "status-http-ban")
	if status != http.StatusOK || !bytes.Equal(replay, banWire) || effects() != [4]int64{afterBan[0], afterBan[1], afterBan[2], afterBan[3] + 1} {
		t.Fatal("HTTPS ban retry after version change did not preserve exact receipt and one attempt charge", status)
	}
	status, _ = invoke("/v1/admin/user-ban", map[string]any{"userID": target.user, "reason": "reviewed"}, actorCookies, actorCSRF, "status-http-ban")
	if status != http.StatusConflict || effects() != [4]int64{afterBan[0], afterBan[1], afterBan[2], afterBan[3] + 2} {
		t.Fatal("changed keyed HTTPS ban intent did not conflict with only one quota charge", status)
	}
	unbanBody := map[string]any{"userID": target.user, "expectedVersion": ban.User.Version}
	beforeUnban := effects()
	status, unbanWire := invoke("/v1/admin/user-unban", unbanBody, actorCookies, actorCSRF, "status-http-unban")
	if status != http.StatusOK {
		t.Fatal("genuine administrator could not unban over HTTPS", status)
	}
	unban := decode(unbanWire, "identity.admin.user-unban", identity.StatusActive, version+2, authority+2)
	if unban.CommandID == ban.CommandID || unban.Revocation.CascadeID == ban.Revocation.CascadeID {
		t.Fatal("HTTPS unban reused the ban operation or cascade")
	}
	assertOldSession(false)
	afterUnban := effects()
	if afterUnban != [4]int64{beforeUnban[0] + 1, beforeUnban[1] + 1, beforeUnban[2] + 1, beforeUnban[3] + 1} {
		t.Fatal("admitted HTTPS unban did not persist one native operation and charge quota exactly once")
	}
	status, replay = invoke("/v1/admin/user-unban", unbanBody, actorCookies, actorCSRF, "status-http-unban")
	if status != http.StatusOK || !bytes.Equal(replay, unbanWire) || effects() != [4]int64{afterUnban[0], afterUnban[1], afterUnban[2], afterUnban[3] + 1} {
		t.Fatal("HTTPS unban retry did not preserve exact receipt and one attempt charge", status)
	}
	fresh, token := referencePasswordLogin(t, ctx, f, &transport, base, origin, nil, config.PasswordSignin.Native, "synthetic-registration-password", "status-http-target@example.invalid")
	if !fresh.SignedIn || fresh.SessionID == target.sessionID || token == oldToken {
		t.Fatal("HTTPS-unbanned target could not obtain a distinct genuine session")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated || current.ValidateAt(time.Now()) != nil {
		t.Fatal("fresh post-HTTPS-unban session is not current", err)
	}
	assertOldSession(false)
}
