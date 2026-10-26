//go:build integration

package reference_test

import (
	"bytes"
	"context"
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
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

func TestReferencePostgresOrganizationLifecycleHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationLifecycle: true, postgresBaseline: true})
}
func TestReferencePostgresOrganizationLifecyclePopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationLifecycle: true, organizationUpgrade: true, postgresBaseline: true})
}
func configureReferenceOrganizationLifecycle(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	configureReferencePasswordProtection(t, c, origin)
	c.PasswordChange, c.HTTPPasswordChange = nil, nil
	c.HTTPPasswordVerification.Transport, c.HTTPPasswordVerification.TrustedOrigins = session.CredentialBearer, nil
	primary := func(op organization.Operation) passwordpg.ActionPrimaryConfig {
		return passwordpg.ActionPrimaryConfig{Action: string(op), Audience: "reference-organization-lifecycle", MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer}
	}
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: string(op), Audience: "reference-organization-lifecycle"})
	}
	c.Organization.Lifecycle = &reference.OrganizationLifecycleConfiguration{Archive: primary(organization.Archive), Restore: primary(organization.Restore)}
	c.HTTPOrganization.Archive, c.HTTPOrganization.Restore = true, true
}

func proveReferenceOrganizationLifecycleSelection(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	for _, mode := range []string{"no-native", "no-proofs", "archive-action", "restore-action", "cookie", "audience", "maximum-age", "core-policy"} {
		candidate, org, selected := c, *c.Organization, *c.Organization.Lifecycle
		candidate.Organization, org.Lifecycle = &org, &selected
		switch mode {
		case "no-native":
			org.Lifecycle = nil
		case "no-proofs":
			candidate.PasswordVerification, candidate.HTTPPasswordVerification = nil, nil
		case "archive-action":
			selected.Archive.Action = string(organization.Restore)
		case "restore-action":
			selected.Restore.Action = string(organization.Archive)
		case "cookie":
			selected.Archive.Transport = session.CredentialCookie
		case "audience":
			selected.Restore.Audience = "other-audience"
		case "maximum-age":
			selected.Restore.MaximumAge = 0
		case "core-policy":
			org.Core.Lifecycle = organization.LifecycleConfig{Version: 1, ProofAudience: "competing"}
		}
		if graph, err := reference.ComposeStores(candidate, deps); err == nil {
			bounded, stop := context.WithTimeout(context.Background(), time.Second)
			_ = graph.Close(bounded)
			stop()
			t.Fatal("invalid lifecycle dependency accepted", mode)
		}
	}
}

// The sender seam captures only delivery. All identity/session/action-proof,
// organization/invitation and protected transaction owners are real public APIs.
func proveReferenceOrganizationLifecycle(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	owner := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	recipient := registerReferenceOrganizationHuman(t, ctx, client, base, origin, features, workers, messages)
	port, err := features.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	invites, err := features.OrganizationInvitations()
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
	created, err := port.Create(ctx, organization.CreateOperationRequest{Authentication: owner.auth, IdempotencyKey: key("lifecycle-create"), Name: "Lifecycle organization", Slug: "reference-lifecycle", CorrelationID: "lifecycle-setup"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real lifecycle setup", err)
	}
	org := created.OrganizationID
	sent, err := invites.Send(ctx, organization.InvitationSendOperationRequest{Authentication: owner.auth, IdempotencyKey: key("lifecycle-invite"), OrganizationID: org, OrganizationVersion: 1, RecipientUserID: recipient.user, RecipientIdentifierID: recipient.identifier, CorrelationID: "lifecycle-setup"}, "127.0.0.1")
	if err != nil || sent.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real pending invitation", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal(err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("invitation delivery absent")
	}
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatal("real invitation proof absent")
	}
	invitationProof := u.Query().Get("token")
	call := func(h organizationTestHuman, path string, body any, requestKey string, device []*http.Cookie) (int, []byte, []*http.Cookie) {
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
		if h.auth.Bearer.Token() != "" {
			r.Header.Set("Authorization", "Bearer "+h.auth.Bearer.Token())
		}
		if requestKey != "" {
			r.Header.Set("Idempotency-Key", requestKey)
		}
		if path == "/v1/session/preauth-issue" {
			r.Header.Set("Origin", origin)
		}
		for _, cookie := range device {
			r.AddCookie(cookie)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		out, readErr := io.ReadAll(io.LimitReader(res.Body, 16385))
		closeErr := res.Body.Close()
		if readErr != nil || closeErr != nil || len(out) > 16384 || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("lifecycle HTTP cleanup/custody")
		}
		return res.StatusCode, out, res.Cookies()
	}
	code, _, device := call(organizationTestHuman{}, "/v1/session/preauth-issue", map[string]string{"method": "password"}, "", nil)
	if code != 200 {
		t.Fatal("lifecycle device", code)
	}
	proof := func(op organization.Operation) passwordhttp.VerificationResponse {
		t.Helper()
		code, wire, _ := call(owner, "/v1/password/verify", map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": string(op), "audience": "reference-organization-lifecycle"}, "", device)
		var out passwordhttp.VerificationResponse
		if code != 200 || json.Unmarshal(wire, &out) != nil || !out.Verified || out.Proof == nil {
			t.Fatal("real lifecycle action proof", op, code, out.Error)
		}
		return out
	}
	archiveProof := proof(organization.Archive)
	body := map[string]any{"organizationID": org, "organizationVersion": 1, "reason": "operator-request", "proofID": archiveProof.Proof.ProofID}
	mutate := func(h organizationTestHuman, op organization.Operation, k string) (int, organizationhttp.MutationResponse) {
		t.Helper()
		path := "/v1/organization/archive"
		if op == organization.Restore {
			path = "/v1/organization/restore"
		}
		code, wire, cookies := call(h, path, body, k, nil)
		var out organizationhttp.MutationResponse
		if json.Unmarshal(wire, &out) != nil || len(cookies) != 0 || bytes.Contains(wire, []byte(h.auth.Bearer.Token())) || bytes.Contains(wire, []byte(archiveProof.Proof.ProofID)) {
			t.Fatal("lifecycle response exported custody")
		}
		return code, out
	}
	if code, out := mutate(recipient, organization.Archive, "wrong-owner"); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("nonowner used archive proof", code)
	}
	if code, out := mutate(owner, organization.Restore, "wrong-action"); code != 403 || out.Committed || out.Recovery != nil {
		t.Fatal("archive proof restored", code)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reference_lifecycle_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic lifecycle outbox failure'; END $$; CREATE TRIGGER reference_lifecycle_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reference_lifecycle_fail()`); err != nil {
		t.Fatal(err)
	}
	if code, out := mutate(owner, organization.Archive, "archive-rollback"); code == 200 || out.Committed || out.CommitOutcome != "not_committed" {
		t.Fatal("archive required effect failed to roll back", code, out.CommitOutcome)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reference_lifecycle_fail ON public.identity_outbox_bindings; DROP FUNCTION reference_lifecycle_fail()`); err != nil {
		t.Fatal(err)
	}
	if v, err := port.Get(ctx, organization.ReadRequest{Authentication: owner.auth, OrganizationID: org, CorrelationID: "after-rollback"}); err != nil || v.Organization.Version != 1 {
		t.Fatal("archive rollback changed authority", err)
	}
	code, archived := mutate(owner, organization.Archive, "reference-archive")
	if code != 200 || !archived.Committed || archived.BeforeVersion != 1 || archived.AfterVersion != 2 || archived.Recovery == nil {
		t.Fatal("HTTP archive", code, archived.Error)
	}
	if code, again := mutate(owner, organization.Archive, "reference-archive"); code != 200 || !reflect.DeepEqual(again, archived) {
		t.Fatal("archive original-key history", code, again.Error)
	}
	if _, err := port.Get(ctx, organization.ReadRequest{Authentication: owner.auth, OrganizationID: org, CorrelationID: "archived-read"}); err == nil {
		t.Fatal("warm ordinary read retained archived authority")
	}
	if v, err := port.GetLifecycle(ctx, organization.ReadRequest{Authentication: owner.auth, OrganizationID: org, CorrelationID: "archive-discovery"}); err != nil || v.Organization.Version != 2 || v.LifecycleState != organization.LifecycleArchived {
		t.Fatal("owner cannot discover archived version", err)
	}
	if _, err := port.GetLifecycle(ctx, organization.ReadRequest{Authentication: recipient.auth, OrganizationID: org, CorrelationID: "foreign-discovery"}); err == nil {
		t.Fatal("nonowner discovered archived organization")
	}
	if code, out := mutate(owner, organization.Archive, "new-archive-key"); code == 200 || out.Committed {
		t.Fatal("consumed archive proof admitted new work", code)
	}
	body["reason"] = "different-reason"
	if code, out := mutate(owner, organization.Archive, "reference-archive"); code != 409 || out.Committed {
		t.Fatal("changed reason adopted original", code)
	}
	body["reason"] = "operator-request"
	restoreProof := proof(organization.Restore)
	body["organizationVersion"], body["proofID"] = 2, restoreProof.Proof.ProofID
	code, restored := mutate(owner, organization.Restore, "reference-restore")
	if code != 200 || !restored.Committed || restored.BeforeVersion != 2 || restored.AfterVersion != 3 || restored.Recovery == nil {
		t.Fatal("HTTP fresh-proof restore", code, restored.Error)
	}
	if v, err := port.Get(ctx, organization.ReadRequest{Authentication: owner.auth, OrganizationID: org, CorrelationID: "restored-read"}); err != nil || v.Organization.Version != 3 || v.Actor.Role != organization.RoleOwner {
		t.Fatal("surviving owner not restored", err)
	}
	if view, err := invites.Get(ctx, organization.InvitationReadRequest{Authentication: owner.auth, OrganizationID: org, ID: sent.InvitationID, CorrelationID: "restored-invitation"}); err != nil || view.Invitation.Status != organization.InvitationCancelled {
		t.Fatal("restore revived pending invitation", err)
	}
	if code, _, _ := call(recipient, "/v1/organization/invitation/accept", map[string]any{"commandID": commandIDForReference(t), "organizationID": org, "organizationVersion": 3, "invitationID": sent.InvitationID, "invitationVersion": 1, "token": invitationProof}, "", nil); code != 403 {
		t.Fatal("restored invitation proof admitted member", code)
	}
	if code, again := mutate(owner, organization.Restore, "reference-restore"); code != 200 || !reflect.DeepEqual(again, restored) {
		t.Fatal("restore original history", code, again.Error)
	}
	var effects, pending, members int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation IN ('identity.organization.archive','identity.organization.restore')), (SELECT count(*) FROM organization.invitations WHERE organization_id=$1 AND state='pending'),(SELECT count(*) FROM organization.memberships WHERE organization_id=$1 AND user_id=$2 AND state='active')`, string(org), string(recipient.user)).Scan(&effects, &pending, &members); err != nil || effects != 2 || pending != 0 || members != 0 {
		t.Fatal("lifecycle singleton/cascade mismatch", err)
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
	selected, err := reference.ComposeFeatures(rebuilt, providers, rebuiltWorkers)
	if err != nil {
		t.Fatal(err)
	}
	if err := selected.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	rebuiltPort, err := selected.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		op       organization.Operation
		original organizationhttp.MutationResponse
		proof    string
		version  uint64
		key      string
	}{{organization.Archive, archived, string(archiveProof.Proof.ProofID), 1, "reference-archive"}, {organization.Restore, restored, string(restoreProof.Proof.ProofID), 2, "reference-restore"}} {
		body["organizationVersion"], body["proofID"] = pair.version, pair.proof
		if code, again := mutate(current, pair.op, pair.key); code != 200 || !reflect.DeepEqual(again, pair.original) {
			t.Fatal("fresh-session original lifecycle history", pair.op, code, again.Error)
		}
		// Explicit recovery uses only returned safe original binding. The graph
		// still enforces current tenant/session/native owner before disclosure.
		r := pair.original.Recovery
		binding := identity.CommandBinding{CommandID: r.CommandID, TenantID: r.TenantID, UserID: r.UserID, ActorID: r.ActorID, ActorKind: r.ActorKind, OperationID: r.OperationID, RecordID: r.RecordID, PolicyID: r.PolicyID, PolicyVersion: r.PolicyVersion, SchemaID: r.SchemaID, SchemaVersion: r.SchemaVersion, CorrelationID: r.CorrelationID}
		if got, err := rebuiltPort.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: current.auth, Binding: binding}); err != nil || got.Receipt.Binding.CommandID != pair.original.CommandID || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("reconstructed lifecycle recovery", err)
		}
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, current.cookies, current.csrf, current.sessionID, f, features)
	if code, out := mutate(current, organization.Restore, "reference-restore"); code == 200 || out.Committed || out.Recovery != nil {
		t.Fatal("logout recovered lifecycle", code)
	}
	if err := rebuilt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := rebuiltPort.GetLifecycle(ctx, organization.ReadRequest{Authentication: owner.auth, OrganizationID: org, CorrelationID: "closed-lifecycle"}); !errors.As(err, &unavailable) {
		t.Fatal("closed graph reached lifecycle owner", err)
	}
}
