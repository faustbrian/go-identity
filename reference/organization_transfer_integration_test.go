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

func TestReferencePostgresOrganizationTransferHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationTransfer: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationTransferPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationTransfer: true, organizationUpgrade: true, postgresBaseline: true})
}

func configureReferenceOrganizationTransfer(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	configureReferencePasswordProtection(t, c, origin)
	c.PasswordChange, c.HTTPPasswordChange = nil, nil
	c.HTTPPasswordVerification.Transport, c.HTTPPasswordVerification.TrustedOrigins = session.CredentialBearer, nil
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: string(organization.OwnerTransfer), Audience: "reference-owner-transfer"})
	c.Organization.OwnerTransfer = &reference.OrganizationOwnerTransferConfiguration{Primary: passwordpg.ActionPrimaryConfig{Action: string(organization.OwnerTransfer), Audience: "reference-owner-transfer", MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer}}
	c.HTTPOrganization.OwnerTransfer = true
}

func proveReferenceOrganizationTransferSelection(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies) {
	t.Helper()
	for _, mode := range []string{"no-native", "no-proofs", "cookie", "csrf", "action", "audience", "maximum-age", "core-audience"} {
		candidate, org, primary := c, *c.Organization, *c.Organization.OwnerTransfer
		candidate.Organization, org.OwnerTransfer = &org, &primary
		field := "reference_organization_transfer"
		switch mode {
		case "no-native":
			org.OwnerTransfer, field = nil, "reference_http_organization"
		case "no-proofs":
			candidate.PasswordVerification = nil
			candidate.HTTPPasswordVerification = nil
		case "cookie":
			primary.Primary.Transport = session.CredentialCookie
		case "csrf":
			primary.Primary.CSRFKeys = c.Session.CSRFKeys
		case "action":
			primary.Primary.Action = "identity.password.change"
		case "audience":
			primary.Primary.Audience, field = "unselected-transfer-audience", "reference_organization_transfer_primary"
		case "maximum-age":
			primary.Primary.MaximumAge, field = 0, "reference_organization_transfer_primary"
		case "core-audience":
			org.Core.OwnerTransferAudience, field = primary.Primary.Audience, "reference_organization"
		}
		graph, err := reference.ComposeStores(candidate, deps)
		if err == nil {
			bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
			closeErr := graph.Close(bounded)
			stop()
			t.Fatal("invalid transfer selection accepted", mode, closeErr)
		}
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || invalid.Field != field {
			t.Fatal("selection failed outside owning transfer boundary", mode, invalid.Field)
		}
	}
}

// Signup, verification delivery, signin, action-proof issuance and transfer all
// use the actual public owners. Native calls only set up the finite organization
// state; no rows, proof records, credentials or transaction stores are invented.
func proveReferenceOrganizationTransfer(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string, fresh func(...string) ([]*http.Cookie, string)) {
	t.Helper()
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	owner := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	target := registerReferenceOrganizationHuman(t, ctx, client, base, origin, features, workers, messages)
	port, err := features.Organizations()
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
	created, err := port.Create(ctx, organization.CreateOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-transfer-create"), Name: "Transfer organization", Slug: "reference-transfer", CorrelationID: "transfer-setup"}, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("transfer organization setup", err)
	}
	org := created.OrganizationID
	added, err := port.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-transfer-member"), OrganizationID: org, OrganizationVersion: 1, UserID: target.user, Role: organization.RoleMember, CorrelationID: "transfer-setup"}, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("transfer member setup", err)
	}
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
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		out, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(out) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("transfer HTTP cleanup/custody")
		}
		return response.StatusCode, out, response.Cookies()
	}
	code, _, device := call(organizationTestHuman{}, "/v1/session/preauth-issue", map[string]string{"method": "password"}, "", nil)
	if code != 200 {
		t.Fatal("transfer device issuance", code)
	}
	code, wire, _ := call(owner, "/v1/password/verify", map[string]string{"password": "synthetic-registration-password", "purpose": "identity.password.verify", "action": string(organization.OwnerTransfer), "audience": "reference-owner-transfer"}, "", device)
	var proof passwordhttp.VerificationResponse
	if code != 200 || json.Unmarshal(wire, &proof) != nil || !proof.Verified || proof.Proof == nil {
		t.Fatal("real transfer proof issuance", code, proof.Error)
	}
	body := map[string]any{"organizationID": org, "targetUserID": target.user, "organizationVersion": 2, "sourceVersion": 1, "targetVersion": 1, "proofID": proof.Proof.ProofID}
	transfer := func(h organizationTestHuman, requestKey string) (int, organizationhttp.MutationResponse) {
		t.Helper()
		code, wire, cookies := call(h, "/v1/organization/owner-transfer", body, requestKey, nil)
		var out organizationhttp.MutationResponse
		if json.Unmarshal(wire, &out) != nil || len(cookies) != 0 || bytes.Contains(wire, []byte(h.auth.Bearer.Token())) || bytes.Contains(wire, []byte(proof.Proof.ProofID)) {
			t.Fatal("transfer response exposed custody")
		}
		return code, out
	}
	if code, out := transfer(target, "wrong-transfer-actor"); code != http.StatusForbidden || out.Committed || out.Recovery != nil {
		t.Fatal("another authenticated user used the owner's proof", code)
	}
	body["targetUserID"] = owner.user
	if code, out := transfer(owner, "self-transfer"); code != http.StatusForbidden || out.Committed {
		t.Fatal("transfer accepted its initiating owner as target", code)
	}
	body["targetUserID"] = target.user
	code, original := transfer(owner, "reference-owner-transfer")
	if code != 200 || !original.Committed || original.BeforeVersion != 2 || original.AfterVersion != 3 || original.MemberID != target.user || original.Recovery == nil {
		t.Fatal("real HTTP transfer unavailable", code, original.Error)
	}
	if got, err := port.Get(ctx, organization.ReadRequest{Authentication: target.auth, OrganizationID: org, CorrelationID: "new-owner-read"}); err != nil || got.Organization.Version != 3 {
		t.Fatal("new owner cannot read transferred organization", err)
	}
	code, again := transfer(owner, "reference-owner-transfer")
	if code != 200 || !reflect.DeepEqual(again, original) {
		t.Fatal("HTTP transfer lost original keyed recovery", code, again.Error)
	}
	if code, out := transfer(owner, "reference-transfer-new-key"); code == 200 || out.Committed {
		t.Fatal("consumed original proof granted new work", code)
	}
	var ownerRole, targetRole string
	var effects, consumed int
	commandBytes, err := base64.RawURLEncoding.DecodeString(string(original.CommandID))
	if err != nil || len(commandBytes) != 16 {
		t.Fatal("original command identity missing")
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT role FROM organization.memberships WHERE organization_id=$1 AND user_id=$2),(SELECT role FROM organization.memberships WHERE organization_id=$1 AND user_id=$3),(SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation='identity.organization.owner-transfer'),(SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id=$4)`, string(org), string(owner.user), string(target.user), commandBytes).Scan(&ownerRole, &targetRole, &effects, &consumed); err != nil || ownerRole != "member" || targetRole != "owner" || effects != 1 || consumed != 1 {
		t.Fatal("transfer did not atomically move ownership/consume proof", err)
	}
	if _, err := port.RemoveMember(ctx, organization.RemoveMemberOperationRequest{Authentication: target.auth, OrganizationID: org, OrganizationVersion: 3, UserID: target.user, MemberVersion: 2, CorrelationID: "last-owner"}, "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("transfer lost last-owner safety", err)
	}
	body["targetVersion"] = 2
	if code, out := transfer(owner, "reference-owner-transfer"); code == 200 || out.Committed {
		t.Fatal("changed transfer intent reused original", code)
	}
	body["targetVersion"] = 1
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
	rebuiltPort, err := currentFeatures.Organizations()
	if err != nil {
		t.Fatal(err)
	}
	recovery := original.Recovery
	binding := identity.CommandBinding{CommandID: recovery.CommandID, TenantID: recovery.TenantID, UserID: recovery.UserID, ActorID: recovery.ActorID, ActorKind: recovery.ActorKind, OperationID: recovery.OperationID, RecordID: recovery.RecordID, PolicyID: recovery.PolicyID, PolicyVersion: recovery.PolicyVersion, SchemaID: recovery.SchemaID, SchemaVersion: recovery.SchemaVersion, CorrelationID: recovery.CorrelationID}
	native, err := rebuiltPort.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: current.auth, Binding: binding})
	if err != nil || native.Receipt.Outcome != identity.CommitOutcomeCommitted || native.Receipt.Binding.CommandID != original.CommandID {
		t.Fatal("reconstructed current-session transfer recovery", err)
	}
	if code, out := transfer(current, "reference-owner-transfer"); code != 200 || !reflect.DeepEqual(out, original) {
		t.Fatal("fresh-session same-key transfer recovery", code, out.Error)
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, current.cookies, current.csrf, current.sessionID, f, features)
	if code, out := transfer(current, "reference-owner-transfer"); code == 200 || out.Committed || out.Recovery != nil {
		t.Fatal("logged-out session recovered transfer", code)
	}
	if err := rebuilt.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var unavailable identity.UnavailableError
	if _, err := rebuiltPort.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: target.auth, Binding: binding}); !errors.As(err, &unavailable) {
		t.Fatal("closed transfer recovery reached native owner", err)
	}
}
