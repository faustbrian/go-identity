//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
)

func TestReferencePostgresOrganizationExpiryHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationExpiry: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationExpiryPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationExpiry: true, organizationUpgrade: true, postgresBaseline: true})
}

// Actual registration, verification, signin, encrypted invitation delivery and
// expiry owners remain public and durable. Native setup avoids spending HTTP
// admin capacity on setup; the selected mutation and predecessor denial use HTTPS.
func proveReferenceOrganizationExpiry(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	owner := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	recipient := registerReferenceOrganizationHuman(t, ctx, client, base, origin, features, workers, messages)
	organizations, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	invitations, err := features.OrganizationInvitations()
	if err != nil {
		t.Fatal(err)
	}
	key := func(value string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	created, err := organizations.Create(ctx, organization.CreateOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-expiry-org"), Name: "Expiry organization", Slug: "reference-expiry", CorrelationID: "expiry-setup"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real expiry organization setup", err)
	}
	org := created.OrganizationID
	sent, err := invitations.Send(ctx, organization.InvitationSendOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-expiry-send"), OrganizationID: org, OrganizationVersion: 1, RecipientUserID: recipient.user, RecipientIdentifierID: recipient.identifier, CorrelationID: "expiry-setup"}, "127.0.0.1")
	if err != nil || sent.Receipt.Outcome != identity.CommitOutcomeCommitted || sent.InvitationID == "" {
		t.Fatal("real expiry invitation setup", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal("real invitation delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("invitation proof was not delivered")
	}
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Query().Get("token") == "" {
		t.Fatal("real delivered invitation proof absent")
	}
	proof := u.Query().Get("token")
	call := func(h organizationTestHuman, path string, body any) (int, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+h.auth.Bearer.Token())
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		out, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(out) > 16384 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || bytes.Contains(out, []byte(h.auth.Bearer.Token())) || bytes.Contains(out, []byte(proof)) {
			t.Fatal("expiry response cleanup/custody")
		}
		return response.StatusCode, out
	}
	body := map[string]any{"organizationID": org, "organizationVersion": 1, "invitationID": sent.InvitationID, "invitationVersion": 1, "reason": "security-withdrawal"}
	expire := func(h organizationTestHuman) (int, organizationhttp.InvitationExpireResponse) {
		t.Helper()
		code, wire := call(h, "/v1/organization/invitation/expire", body)
		var out organizationhttp.InvitationExpireResponse
		if json.Unmarshal(wire, &out) != nil {
			t.Fatal("invalid expiry response")
		}
		return code, out
	}
	if code, out := expire(recipient); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("recipient exercised manager expiry", code)
	}
	body["reason"] = "unregistered"
	if code, out := expire(owner); code != 400 || out.Committed || out.Recovery != nil {
		t.Fatal("unregistered reason was accepted", code)
	}
	body["reason"] = "security-withdrawal"
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reference_expiry_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic expiry outbox failure'; END $$; CREATE TRIGGER reference_expiry_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reference_expiry_fail()`); err != nil {
		t.Fatal(err)
	}
	code, rolledBack := expire(owner)
	if code == 200 || rolledBack.Committed || rolledBack.CommitOutcome != "not_committed" || rolledBack.State != "" {
		t.Fatal("required expiry effect did not roll back", code, rolledBack.CommitOutcome)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reference_expiry_fail ON public.identity_outbox_bindings; DROP FUNCTION reference_expiry_fail()`); err != nil {
		t.Fatal(err)
	}
	view, err := invitations.Get(ctx, organization.InvitationReadRequest{Authentication: owner.auth, OrganizationID: org, ID: sent.InvitationID, CorrelationID: "expiry-after-rollback"})
	if err != nil || view.Invitation.Status != organization.InvitationPending || view.Invitation.Version != 1 {
		t.Fatal("rollback consumed pending invitation", err)
	}
	code, original := expire(owner)
	if code != 200 || !original.Committed || original.State != "expired" || original.InvitationID != sent.InvitationID || original.BeforeVersion != 1 || original.AfterVersion != 2 || original.Recovery == nil {
		t.Fatal("real HTTP expiry failed", code, original.Error)
	}
	if view, err := organizations.Get(ctx, organization.ReadRequest{Authentication: owner.auth, OrganizationID: org, CorrelationID: "expiry-org-unchanged"}); err != nil || view.Organization.Version != 1 || view.Actor.Role != organization.RoleOwner {
		t.Fatal("expiry changed organization membership or authority epoch", err)
	}
	if code, out := expire(owner); code != 200 || !reflect.DeepEqual(out, original) {
		t.Fatal("natural expiry repeat replaced original", code, out.Error)
	}
	body["reason"] = "administrative-cleanup"
	if code, out := expire(owner); code != 409 || out.Committed {
		t.Fatal("changed registered reason adopted history", code)
	}
	body["reason"], body["organizationVersion"] = "security-withdrawal", 2
	if code, out := expire(owner); code != 409 || out.Committed {
		t.Fatal("changed organization epoch adopted history", code)
	}
	body["organizationVersion"] = 1
	if code, _ := call(recipient, "/v1/organization/invitation/accept", map[string]any{"commandID": commandIDForReference(t), "organizationID": org, "organizationVersion": 1, "invitationID": sent.InvitationID, "invitationVersion": 1, "token": proof}); code != 403 {
		t.Fatal("expired delivered proof admitted membership", code)
	}
	commandBytes, err := base64.RawURLEncoding.DecodeString(string(original.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var effects, events, audits, members int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.expire'),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='invitation.expired.v1'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.expire_invitation' AND r.outcome=1),
 (SELECT count(*) FROM organization.memberships WHERE organization_id=$3 AND user_id=$4 AND state='active')`, string(sent.InvitationID), commandBytes, string(org), string(recipient.user)).Scan(&effects, &events, &audits, &members); err != nil || effects != 1 || events != 1 || audits != 1 || members != 0 {
		t.Fatal("expiry lost singleton effects or admitted member", err)
	}
	currentCookies, currentCSRF := fresh()
	current := organizationHumanFromSession(t, ctx, sessions, currentCookies, currentCSRF)
	rebuilt, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := rebuilt.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	rebuiltWorkers, err := reference.ComposeWorkers(rebuilt, providers, workerConfigs...)
	if err != nil {
		t.Fatal(err)
	}
	currentFeatures, err := reference.ComposeFeatures(rebuilt, providers, rebuiltWorkers)
	if err != nil {
		t.Fatal(err)
	}
	if err := currentFeatures.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	currentInvitations, err := currentFeatures.OrganizationInvitations()
	if err != nil {
		t.Fatal(err)
	}
	r := organization.InvitationExpireOperationRequest{Authentication: current.auth, OrganizationID: org, OrganizationVersion: 1, InvitationID: sent.InvitationID, InvitationVersion: 1, Reason: "security-withdrawal", CorrelationID: "reconstructed-expiry"}
	if got, err := currentInvitations.Expire(ctx, r, "127.0.0.1"); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding.CommandID != original.CommandID {
		t.Fatal("reconstructed fresh-session expiry history", err)
	}
	if code, out := expire(current); code != 200 || !reflect.DeepEqual(out, original) {
		t.Fatal("fresh-session HTTP expiry history", code, out.Error)
	}
	foreign := r
	foreign.Authentication.TenantID = "unconfigured-tenant"
	if got, err := currentInvitations.Expire(ctx, foreign, "127.0.0.1"); err == nil || got.Receipt.Binding.CommandID != "" {
		t.Fatal("expiry crossed graph tenant boundary")
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, current.cookies, current.csrf, current.sessionID, f, features)
	if code, out := expire(current); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("logged-out manager recovered expiry", code)
	}
	if got, err := currentInvitations.Expire(ctx, r, "127.0.0.1"); err == nil || got.Receipt.Binding.CommandID != "" {
		t.Fatal("logged-out manager recovered native expiry")
	}
	if err := rebuilt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := currentInvitations.Expire(ctx, r, "127.0.0.1"); !errors.As(err, &unavailable) {
		t.Fatal("retained expiry handle reached native after close", err)
	}
}
