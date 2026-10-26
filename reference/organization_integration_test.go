//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Use the existing real registration, captured verification delivery and
// password-signin graph; no organization or session is seeded by this fixture.
func TestReferencePostgresOrganizationHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, postgresBaseline: true})
}

func TestReferencePostgresOrganizationPopulatedUpgradeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{organization: true, organizationUpgrade: true, postgresBaseline: true})
}

type referenceOrganizationPolicy struct{}

func (referenceOrganizationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 && c.Request.Subject.Kind == authorization.SubjectUser {
		// Invitation owners read delivery metadata whose resource is the
		// intended recipient. The native invitation reader checks ownership;
		// requiring self-ID equality here would hide an already committed send.
		if c.Request.Action == "identity.delivery.status-get" && c.Request.Resource.Type == "identity.user" {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
		switch c.Request.Action {
		case "identity.organization.create", "identity.organization.create.recover", "identity.organization.update", "identity.organization.update.recover", "identity.organization.get", "identity.organization.member.list", "identity.organization.member.add", "identity.organization.member.add.recover", "identity.organization.member.update", "identity.organization.member.update.recover", "identity.organization.member.remove", "identity.organization.member.remove.recover", "identity.organization.invitation-send", "identity.organization.invitation-send.recover", "identity.organization.invitation.accept", "identity.organization.invitation.accept.recover", "identity.organization.invitation.resend", "identity.organization.invitation.resend.recover", "identity.organization.invitation.cancel", "identity.organization.invitation.cancel.recover", "identity.organization.invitation.reject", "identity.organization.invitation.reject.recover", "identity.organization.invitation.get", "identity.organization.invitation.list-mine":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func configureReferenceOrganization(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	custody, err := organizationpg.NewOperationCustodyConfig("organization", map[string][]byte{"organization": bytes.Repeat([]byte{141}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	counters := c.PasswordSignup.Counters
	counters.EnforceLockouts = true
	selectID := func(ctx context.Context) (organization.ID, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		id, err := identity.NewSubjectID()
		return organization.ID(id), err
	}
	c.Organization = &reference.OrganizationConfiguration{Core: organization.Config{MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := identity.ParseSubjectID(string(id))
		return err
	}}, Repository: organizationpg.Config{MaximumDuration: time.Second}, Counters: counters, Custody: custody, ConfigurationID: "reference-organization-v1", SelectOrganizationID: selectID}
	// Keep the original registration provider/policy unchanged. Invitations
	// explicitly select a retained second profile with their required dedupe.
	policy := c.Delivery.Enqueue.Policies[1]
	policy.DedupeTTL = 72 * time.Hour
	c.Delivery.Enqueue.Policies[2] = policy
	c.Delivery.Enqueue.Custody.ProviderProfiles[2] = deliverypg.ProviderProfile{Provider: "reference-invitation", PolicyVersion: 2}
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "organization-invitation", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096})
	issuer, preparation := c.PasswordSignup.Issuer, c.PasswordSignup.Preparation
	issuer.Audience, issuer.Crypto.Clock, preparation.Clock = "organization-invitation", nil, nil
	issuer.Crypto.Limits.MaxLifetime = 15 * time.Minute
	c.Organization.Invitations = &reference.OrganizationInvitationConfiguration{Policy: organization.InvitationConfig{Audience: issuer.Audience, Lifetime: 15 * time.Minute, MaximumPending: 100}, Issuer: issuer, Preparation: preparation, ConfigurationID: "reference-organization-invitation-v1", SelectInvitationID: selectID, TemplateID: "organization-invitation", TemplateVersion: 1, PolicyVersion: 2, ProviderVersion: 2, LocaleChain: []string{"en"}, Endpoint: origin + "/invitation", ScopeKey: [32]byte{144}}
	c.HTTPOrganization = &reference.HTTPOrganizationConfiguration{Create: true, Update: true, Get: true, MemberList: true, MemberAdd: true, MemberUpdate: true, MemberRemove: true, InvitationGet: true, InvitationListMine: true, InvitationSend: true, InvitationAccept: true, InvitationResend: true, InvitationCancel: true, InvitationReject: true, SafeNamespace: "reference-organization-safe", EmergencyMaximumKeys: 64, Degraded: func(ctx context.Context, _ identityhttp.SafeRateEvent) error { return ctx.Err() }, SecretNamespace: "reference-organization-secret", SecretKey: [32]byte{143}, AdminNamespace: "reference-organization", AdminKey: [32]byte{142}, Denied: func(ctx context.Context, _ organizationhttp.AdminRateEvent) error {
		// This success-path fixture does not expect a rate denial. Failing the
		// callback cannot permit a denied request or fake successful auditing.
		t.Error("unexpected organization administrative denial")
		return ctx.Err()
	}}
}

func proveReferenceOrganizationHTTPS(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, features reference.FeatureSet, workers reference.WorkerSet, workerConfigs []deliverypg.WorkerConfig, client *http.Client, base, origin string, messages <-chan string, cookies []*http.Cookie, csrf string) {
	t.Helper()
	if len(cookies) != 1 {
		t.Fatal("genuine signed-in session required")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	owner := organizationHumanFromSession(t, ctx, sessions, cookies, csrf)
	recipient := registerReferenceOrganizationHuman(t, ctx, client, base, origin, features, workers, messages)
	call := func(h organizationTestHuman, method, path string, value any, key string) (int, []byte) {
		t.Helper()
		var wire []byte
		if value != nil {
			var err error
			wire, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer clear(wire)
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+h.auth.Bearer.Token())
		if value != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("organization HTTPS failed", err)
		}
		payload, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closed := response.Body.Close()
		if e != nil || closed != nil || len(payload) > 1<<20 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || bytes.Contains(payload, []byte(h.auth.Bearer.Token())) {
			t.Fatal("organization response custody/cleanup")
		}
		return response.StatusCode, payload
	}
	create := func(slug, key string) organizationhttp.MutationResponse {
		t.Helper()
		value := map[string]string{"name": "Reference organization", "slug": slug}
		code, wire := call(owner, http.MethodPost, "/v1/organization/create", value, key)
		var out organizationhttp.MutationResponse
		if code != 200 || json.Unmarshal(wire, &out) != nil || !out.Committed || out.OrganizationID == "" || out.Recovery == nil {
			t.Fatal("Reference organization creation unavailable after genuine signin", code)
		}
		again, payload := call(owner, http.MethodPost, "/v1/organization/create", value, key)
		var repeated organizationhttp.MutationResponse
		if again != 200 || json.Unmarshal(payload, &repeated) != nil || repeated.CommandID != out.CommandID || repeated.OrganizationID != out.OrganizationID {
			t.Fatal("Reference create retry replaced original", again)
		}
		return out
	}
	first := create("reference-member-organization", "reference-organization-original-create")
	read := func(h organizationTestHuman, id organization.ID, want int) organizationhttp.ReadResponse {
		t.Helper()
		code, wire := call(h, http.MethodGet, "/v1/organization/get?organizationID="+string(id), nil, "")
		if code != want {
			t.Fatal("organization scoped read", code, want)
		}
		var out organizationhttp.ReadResponse
		if code == 200 && (json.Unmarshal(wire, &out) != nil || out.Organization.ID != id || out.Membership.UserID != h.user) {
			t.Fatal("current organization read mismatched")
		}
		return out
	}
	mutate := func(h organizationTestHuman, path string, body any, key string, want int) organizationhttp.MutationResponse {
		t.Helper()
		code, wire := call(h, http.MethodPost, path, body, key)
		var out organizationhttp.MutationResponse
		if code != want || json.Unmarshal(wire, &out) != nil || want == 200 && (!out.Committed || out.Recovery == nil) {
			t.Fatal("Reference organization update", path, code, want)
		}
		return out
	}
	metadata := map[string]any{"organizationID": first.OrganizationID, "organizationVersion": uint64(1), "name": "Updated reference", "slug": "updated-reference"}
	updated := mutate(owner, "/v1/organization/update", metadata, "reference-original-metadata-update", 200)
	retried := mutate(owner, "/v1/organization/update", metadata, "reference-original-metadata-update", 200)
	if updated.CommandID != retried.CommandID || updated.BeforeVersion != 1 || updated.AfterVersion != 2 {
		t.Fatal("Reference metadata retry replaced original command or version")
	}
	metadata["name"] = "Changed original intent"
	mutate(owner, "/v1/organization/update", metadata, "reference-original-metadata-update", 409)
	metadata["name"], metadata["organizationVersion"] = "Updated reference", uint64(2)
	mutate(recipient, "/v1/organization/update", metadata, "reference-foreign-metadata-update", 403)
	currentOrganization := read(owner, first.OrganizationID, 200)
	if currentOrganization.Organization.Name != "Updated reference" || currentOrganization.Organization.Slug != "updated-reference" || currentOrganization.Organization.Version != 2 {
		t.Fatal("Reference metadata update was not current or repeated its effect")
	}
	read(recipient, first.OrganizationID, 403)
	add := map[string]any{"organizationID": first.OrganizationID, "userID": recipient.user, "role": "member", "organizationVersion": currentOrganization.Organization.Version, "memberVersion": uint64(0)}
	code, wire := call(owner, http.MethodPost, "/v1/organization/member/add", add, "reference-member-original-add")
	var added organizationhttp.MutationResponse
	if code != 200 || json.Unmarshal(wire, &added) != nil || !added.Committed {
		t.Fatal("Reference member admission", code)
	}
	member := read(recipient, first.OrganizationID, 200)
	code, wire = call(owner, http.MethodGet, "/v1/organization/member/list?organizationID="+string(first.OrganizationID)+"&limit=10", nil, "")
	var listed organizationhttp.ReadResponse
	if code != 200 || json.Unmarshal(wire, &listed) != nil || listed.Organization.ID != first.OrganizationID || listed.Members == nil || len(*listed.Members) != 2 {
		t.Fatal("Reference scoped membership listing", code)
	}
	seenMembers := make(map[identity.UserID]organization.Role)
	for _, entry := range *listed.Members {
		seenMembers[entry.UserID] = entry.Role
	}
	if seenMembers[owner.user] != organization.RoleOwner || seenMembers[recipient.user] != organization.RoleMember {
		t.Fatal("Reference membership page lost actual owner/member")
	}
	role := map[string]any{"organizationID": first.OrganizationID, "userID": recipient.user, "role": "administrator", "organizationVersion": member.Organization.Version, "memberVersion": member.Membership.Version}
	promoted := mutate(owner, "/v1/organization/member/update", role, "reference-original-role-update", 200)
	repeatedRole := mutate(owner, "/v1/organization/member/update", role, "reference-original-role-update", 200)
	if repeatedRole.CommandID != promoted.CommandID || promoted.BeforeVersion != 3 || promoted.AfterVersion != 4 {
		t.Fatal("Reference role retry replaced original command or version")
	}
	role["role"] = "member"
	mutate(owner, "/v1/organization/member/update", role, "reference-original-role-update", 409)
	member = read(recipient, first.OrganizationID, 200)
	if member.Membership.Role != organization.RoleAdministrator || member.Membership.Version != 2 {
		t.Fatal("Reference role update did not advance current membership")
	}
	metadata["organizationVersion"], metadata["name"] = member.Organization.Version, "Administrator update"
	mutate(recipient, "/v1/organization/update", metadata, "reference-administrator-metadata-update", 200)
	member = read(recipient, first.OrganizationID, 200)
	role["organizationVersion"], role["memberVersion"] = member.Organization.Version, member.Membership.Version
	mutate(owner, "/v1/organization/member/update", role, "reference-original-role-demotion", 200)
	member = read(recipient, first.OrganizationID, 200)
	if member.Membership.Role != organization.RoleMember || member.Membership.Version != 3 {
		t.Fatal("Reference role demotion retained old member authority")
	}
	metadata["organizationVersion"] = member.Organization.Version
	mutate(recipient, "/v1/organization/update", metadata, "reference-withdrawn-administrator", 403)
	lastOwner := map[string]any{"organizationID": first.OrganizationID, "userID": owner.user, "role": "member", "organizationVersion": member.Organization.Version, "memberVersion": uint64(1)}
	mutate(owner, "/v1/organization/member/update", lastOwner, "reference-last-owner-role-denial", 409)
	remove := map[string]any{"organizationID": first.OrganizationID, "userID": recipient.user, "organizationVersion": member.Organization.Version, "memberVersion": member.Membership.Version}
	code, wire = call(owner, http.MethodPost, "/v1/organization/member/remove", remove, "")
	var removed organizationhttp.MutationResponse
	if code != 200 || json.Unmarshal(wire, &removed) != nil || !removed.Committed {
		t.Fatal("Reference member removal", code)
	}
	read(recipient, first.OrganizationID, 403)
	// A separate organization demonstrates never-member recipient acceptance,
	// independently of the direct admission/removal profile above.
	second := create("reference-invitation-organization", "reference-invitation-original-create")
	sentBody := map[string]any{"organizationID": second.OrganizationID, "organizationVersion": uint64(1), "recipientUserID": recipient.user, "recipientIdentifierID": recipient.identifier}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation-send", sentBody, "reference-original-invitation-send")
	var sent organizationhttp.InvitationSendResponse
	decodeErr := json.Unmarshal(wire, &sent)
	if code != 200 || decodeErr != nil || !sent.Committed || sent.InvitationID == "" {
		t.Fatal("Reference original-key invitation send", code, sent.CommitOutcome, sent.Error)
	}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation-send", sentBody, "reference-original-invitation-send")
	var repeated organizationhttp.InvitationSendResponse
	if code != 200 || json.Unmarshal(wire, &repeated) != nil || repeated.CommandID != sent.CommandID || repeated.InvitationID != sent.InvitationID {
		t.Fatal("invitation retry regenerated original", code)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal("actual Reference invitation delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("invitation delivery absent")
	}
	delivered, err := url.Parse(link)
	if err != nil || delivered.Scheme != "https" || delivered.Host == "" {
		t.Fatal("invitation link invalid")
	}
	proof := delivered.Query().Get("token")
	if proof == "" {
		t.Fatal("invitation proof missing")
	}
	resendBody := map[string]any{"organizationID": second.OrganizationID, "organizationVersion": uint64(1), "invitationID": sent.InvitationID, "invitationVersion": uint64(1)}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation/resend", resendBody, "reference-original-invitation-resend")
	var resent organizationhttp.InvitationResendResponse
	if code != 200 || json.Unmarshal(wire, &resent) != nil || !resent.Committed || resent.InvitationID != sent.InvitationID || resent.BeforeVersion != 1 || resent.AfterVersion != 2 || resent.DeliveryState != "queued" {
		t.Fatal("Reference original-key invitation resend", code, resent.CommitOutcome, resent.Error)
	}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation/resend", resendBody, "reference-original-invitation-resend")
	var resentRetry organizationhttp.InvitationResendResponse
	if code != 200 || json.Unmarshal(wire, &resentRetry) != nil || resentRetry.CommandID != resent.CommandID || resentRetry.BeforeVersion != 1 || resentRetry.AfterVersion != 2 || resentRetry.DeliveryState != "queued" {
		t.Fatal("HTTP resend retry replaced original outcome", code)
	}
	predecessorCommand, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	predecessor := map[string]any{"commandID": predecessorCommand, "organizationID": second.OrganizationID, "invitationID": sent.InvitationID, "organizationVersion": uint64(1), "invitationVersion": uint64(2), "token": proof}
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/accept", predecessor, ""); code == 200 {
		t.Fatal("superseded invitation proof accepted through HTTP")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal("actual Reference successor delivery", err)
	}
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("successor delivery absent")
	}
	successorLink, err := url.Parse(link)
	if err != nil || successorLink.Query().Get("token") == "" || successorLink.Query().Get("token") == proof {
		t.Fatal("successor proof absent or predecessor reused")
	}
	proof = successorLink.Query().Get("token")
	code, wire = call(owner, http.MethodGet, "/v1/organization/invitation/get?organizationID="+string(second.OrganizationID)+"&invitationID="+string(sent.InvitationID), nil, "")
	var currentInvitation organizationhttp.InvitationReadResponse
	if code != 200 || json.Unmarshal(wire, &currentInvitation) != nil || currentInvitation.Invitation.Version != 2 || sent.Invitation == nil || !currentInvitation.Invitation.ExpiresAt.Equal(sent.Invitation.ExpiresAt) || currentInvitation.Invitation.Role != sent.Invitation.Role {
		t.Fatal("Reference resend renewed expiry, changed role or lost successor", code)
	}
	var resendEffects, resendDeliveries, resendEvents int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),
 (SELECT count(*) FROM organization.command_effects e JOIN identity.delivery_intents d ON d.effect_id=e.delivery_effect_id AND d.tenant_id=e.tenant_id WHERE e.command_id=$1),
 (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1 AND topic='invitation.resent.v1')`, string(resent.CommandID)).Scan(&resendEffects, &resendDeliveries, &resendEvents); err != nil || resendEffects != 1 || resendDeliveries != 1 || resendEvents != 1 {
		t.Fatal("Reference keyed resend did not conserve singleton effects", err)
	}
	code, wire = call(recipient, http.MethodGet, "/v1/organization/invitation/list-mine", nil, "")
	var invitations organizationhttp.InvitationListMineResponse
	if code != 200 || json.Unmarshal(wire, &invitations) != nil || len(invitations.Invitations) != 1 || invitations.Invitations[0].ID != sent.InvitationID || bytes.Contains(wire, []byte(proof)) {
		t.Fatal("Reference current recipient discovery", code)
	}
	code, _ = call(recipient, http.MethodGet, "/v1/organization/invitation/get?organizationID="+string(second.OrganizationID)+"&invitationID="+string(sent.InvitationID), nil, "")
	if code != 403 {
		t.Fatal("recipient gained owner-only invitation read", code)
	}
	original, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	accept := map[string]any{"commandID": original, "organizationID": second.OrganizationID, "invitationID": sent.InvitationID, "organizationVersion": uint64(1), "invitationVersion": uint64(2), "token": proof}
	if code, _ := call(owner, http.MethodPost, "/v1/organization/invitation/accept", accept, ""); code != 403 {
		t.Fatal("foreign invitation recipient accepted", code)
	}
	code, wire = call(recipient, http.MethodPost, "/v1/organization/invitation/accept", accept, "")
	var accepted organizationhttp.InvitationAcceptResponse
	acceptDecodeErr := json.Unmarshal(wire, &accepted)
	if code != 200 || acceptDecodeErr != nil || !accepted.Committed || accepted.CommandID != original || accepted.InvitationID != sent.InvitationID || accepted.Recovery == nil || bytes.Contains(wire, []byte(proof)) {
		t.Fatal("Reference once-only invitation acceptance", code, accepted.CommitOutcome, accepted.Error)
	}
	read(recipient, second.OrganizationID, 200)
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/accept", accept, ""); code == 200 {
		t.Fatal("consumed invitation proof executed again")
	}
	var effects int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM organization.command_effects WHERE command_id=$1", string(original)).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("acceptance original effects not exactly once", err)
	}
	var invitationEvents, membershipEvents int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER (WHERE topic='invitation.accepted.v1'), count(*) FILTER (WHERE topic='membership.created.v1') FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$1`, string(original)).Scan(&invitationEvents, &membershipEvents); err != nil || invitationEvents != 1 || membershipEvents != 1 {
		t.Fatal("acceptance lost distinct atomic invitation/membership events", err)
	}
	// A separate pending invitation proves cancellation rather than inferring
	// revocation from an already accepted/consumed predecessor.
	third := create("reference-cancel-organization", "reference-cancel-original-create")
	cancelSend := map[string]any{"organizationID": third.OrganizationID, "organizationVersion": uint64(1), "recipientUserID": recipient.user, "recipientIdentifierID": recipient.identifier}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation-send", cancelSend, "reference-cancel-original-send")
	var cancelSent organizationhttp.InvitationSendResponse
	if code != 200 || json.Unmarshal(wire, &cancelSent) != nil || !cancelSent.Committed || cancelSent.InvitationID == "" {
		t.Fatal("Reference cancellation invitation not issued", code)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal("Reference cancellation proof delivery", err)
	}
	var cancelLink string
	select {
	case cancelLink = <-messages:
	case <-ctx.Done():
		t.Fatal("cancellation invitation delivery absent")
	}
	parsedCancelLink, err := url.Parse(cancelLink)
	if err != nil || parsedCancelLink.Query().Get("token") == "" {
		t.Fatal("cancellation proof absent")
	}
	cancelProof := parsedCancelLink.Query().Get("token")
	parsedProof, err := capability.ParseProof(cancelProof, c.Organization.Invitations.Issuer.Crypto.Limits)
	if err != nil {
		t.Fatal("delivered cancellation predecessor proof invalid")
	}
	beforeCancel, err := features.OrganizationInvitations()
	if err != nil {
		t.Fatal(err)
	}
	acceptBeforeCancel, err := beforeCancel.PrepareAcceptance(ctx, organization.InvitationAcceptRequest{Authentication: recipient.auth, CommandID: commandIDForReference(t), OrganizationID: third.OrganizationID, ID: cancelSent.InvitationID, OrganizationVersion: 1, InvitationVersion: 1, Proof: parsedProof, CorrelationID: "before-reference-cancel"}, "127.0.0.1")
	if err != nil {
		t.Fatal("actual cancellation predecessor was not admissible", err)
	}
	cancelBody := map[string]any{"organizationID": third.OrganizationID, "organizationVersion": uint64(1), "invitationID": cancelSent.InvitationID, "invitationVersion": uint64(1)}
	if code, _ := call(owner, http.MethodPost, "/v1/organization/invitation/cancel", cancelBody, "forbidden-key"); code != 400 {
		t.Fatal("natural cancellation accepted a client key", code)
	}
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/cancel", cancelBody, ""); code != 403 {
		t.Fatal("recipient obtained manager cancellation authority", code)
	}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation/cancel", cancelBody, "")
	var cancelled organizationhttp.InvitationCancelResponse
	if code != 200 || json.Unmarshal(wire, &cancelled) != nil || !cancelled.Committed || cancelled.State != "cancelled" || cancelled.InvitationID != cancelSent.InvitationID || cancelled.BeforeVersion != 1 || cancelled.AfterVersion != 2 || cancelled.Recovery == nil || cancelled.MemberID != "" || bytes.Contains(wire, []byte(cancelProof)) {
		t.Fatal("Reference natural cancellation did not commit", code, cancelled.CommitOutcome, cancelled.Error)
	}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation/cancel", cancelBody, "")
	var cancelledRetry organizationhttp.InvitationCancelResponse
	if code != 200 || json.Unmarshal(wire, &cancelledRetry) != nil || cancelledRetry.CommandID != cancelled.CommandID || cancelledRetry.State != "cancelled" {
		t.Fatal("Reference cancellation repeat replaced original history", code)
	}
	if out, err := acceptBeforeCancel.Execute(ctx); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("already-prepared acceptance survived cancellation")
	}
	cancelAccept := map[string]any{"commandID": commandIDForReference(t), "organizationID": third.OrganizationID, "invitationID": cancelSent.InvitationID, "organizationVersion": uint64(1), "invitationVersion": uint64(1), "token": cancelProof}
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/accept", cancelAccept, ""); code == 200 {
		t.Fatal("cancelled proof accepted through HTTP")
	}
	var cancelEffects, cancelEvents, cancelMembers int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.cancel'),
 (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$2 AND topic='invitation.cancelled.v1'),
 (SELECT count(*) FROM organization.memberships WHERE tenant_id=$3 AND organization_id=$4 AND user_id=$5 AND state='active')`, string(cancelSent.InvitationID), string(cancelled.CommandID), string(otpTenant), string(third.OrganizationID), string(recipient.user)).Scan(&cancelEffects, &cancelEvents, &cancelMembers); err != nil || cancelEffects != 1 || cancelEvents != 1 || cancelMembers != 0 {
		t.Fatal("Reference cancellation failed atomic singleton/no-membership effects", err)
	}
	// A separate pending invitation proves rejection rather than inferring
	// revocation from an already accepted/consumed predecessor.
	fourth := create("reference-reject-organization", "reference-reject-original-create")
	rejectSend := map[string]any{"organizationID": fourth.OrganizationID, "organizationVersion": uint64(1), "recipientUserID": recipient.user, "recipientIdentifierID": recipient.identifier}
	code, wire = call(owner, http.MethodPost, "/v1/organization/invitation-send", rejectSend, "reference-reject-original-send")
	var rejectSent organizationhttp.InvitationSendResponse
	if code != 200 || json.Unmarshal(wire, &rejectSent) != nil || !rejectSent.Committed || rejectSent.InvitationID == "" {
		t.Fatal("Reference rejection invitation not issued", code)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal("Reference rejection proof delivery", err)
	}
	var rejectLink string
	select {
	case rejectLink = <-messages:
	case <-ctx.Done():
		t.Fatal("rejection invitation delivery absent")
	}
	parsedRejectLink, err := url.Parse(rejectLink)
	if err != nil || parsedRejectLink.Query().Get("token") == "" {
		t.Fatal("rejection proof absent")
	}
	rejectProof := parsedRejectLink.Query().Get("token")
	parsedRejectProof, err := capability.ParseProof(rejectProof, c.Organization.Invitations.Issuer.Crypto.Limits)
	if err != nil {
		t.Fatal("delivered rejection predecessor proof invalid")
	}
	beforeReject, err := features.OrganizationInvitations()
	if err != nil {
		t.Fatal(err)
	}
	acceptBeforeReject, err := beforeReject.PrepareAcceptance(ctx, organization.InvitationAcceptRequest{Authentication: recipient.auth, CommandID: commandIDForReference(t), OrganizationID: fourth.OrganizationID, ID: rejectSent.InvitationID, OrganizationVersion: 1, InvitationVersion: 1, Proof: parsedRejectProof, CorrelationID: "before-reference-reject"}, "127.0.0.1")
	if err != nil {
		t.Fatal("actual rejection predecessor was not admissible", err)
	}
	rejectBody := map[string]any{"organizationID": fourth.OrganizationID, "organizationVersion": uint64(1), "invitationID": rejectSent.InvitationID, "invitationVersion": uint64(1)}
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/reject", rejectBody, "forbidden-key"); code != 400 {
		t.Fatal("natural rejection accepted a client key", code)
	}
	if code, _ := call(owner, http.MethodPost, "/v1/organization/invitation/reject", rejectBody, ""); code != 403 {
		t.Fatal("manager obtained intended-recipient rejection authority", code)
	}
	code, wire = call(recipient, http.MethodPost, "/v1/organization/invitation/reject", rejectBody, "")
	var rejected organizationhttp.InvitationRejectResponse
	if code != 200 || json.Unmarshal(wire, &rejected) != nil || !rejected.Committed || rejected.State != "rejected" || rejected.InvitationID != rejectSent.InvitationID || rejected.BeforeVersion != 1 || rejected.AfterVersion != 2 || rejected.Recovery == nil || rejected.MemberID != "" || bytes.Contains(wire, []byte(rejectProof)) {
		t.Fatal("Reference natural rejection did not commit", code, rejected.CommitOutcome, rejected.Error)
	}
	code, wire = call(recipient, http.MethodPost, "/v1/organization/invitation/reject", rejectBody, "")
	var rejectedRetry organizationhttp.InvitationRejectResponse
	if code != 200 || json.Unmarshal(wire, &rejectedRetry) != nil || rejectedRetry.CommandID != rejected.CommandID || rejectedRetry.State != "rejected" {
		t.Fatal("Reference rejection repeat replaced original history", code)
	}
	if out, err := acceptBeforeReject.Execute(ctx); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("already-prepared acceptance survived rejection")
	}
	rejectAccept := map[string]any{"commandID": commandIDForReference(t), "organizationID": fourth.OrganizationID, "invitationID": rejectSent.InvitationID, "organizationVersion": uint64(1), "invitationVersion": uint64(1), "token": rejectProof}
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/accept", rejectAccept, ""); code == 200 {
		t.Fatal("rejected proof accepted through HTTP")
	}
	var rejectEffects, rejectEvents, rejectMembers int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.reject'),
 (SELECT count(*) FROM public.outbox_messages WHERE metadata->>'identity.command_id'=$2 AND topic='invitation.rejected.v1'),
 (SELECT count(*) FROM organization.memberships WHERE tenant_id=$3 AND organization_id=$4 AND user_id=$5 AND state='active')`, string(rejectSent.InvitationID), string(rejected.CommandID), string(otpTenant), string(fourth.OrganizationID), string(recipient.user)).Scan(&rejectEffects, &rejectEvents, &rejectMembers); err != nil || rejectEffects != 1 || rejectEvents != 1 || rejectMembers != 0 {
		t.Fatal("Reference rejection failed atomic singleton/no-membership effects", err)
	}
	rebuilt, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("reconstruct Reference organization graph", err)
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
	current, err := reference.ComposeFeatures(rebuilt, providers, rebuiltWorkers)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.Initialize(ctx); err != nil {
		t.Fatal("fresh Reference initialization", err)
	}
	invitationsOwner, err := current.OrganizationInvitations()
	if err != nil {
		t.Fatal(err)
	}
	scope := accepted.Recovery
	binding := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: scope.OperationID, RecordID: scope.RecordID, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, SchemaID: scope.SchemaID, SchemaVersion: scope.SchemaVersion, CorrelationID: scope.CorrelationID}
	recovery := organization.InvitationAcceptRecoveryRequest{Authentication: recipient.auth, Binding: binding, OrganizationID: accepted.OrganizationID}
	recovered, err := invitationsOwner.RecoverAccept(ctx, recovery)
	if err != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Receipt.Binding != binding || recovered.InvitationID != sent.InvitationID {
		t.Fatal("fresh Reference original acceptance recovery", err)
	}
	resendKey, err := identity.NewIdempotencyKey([]byte("reference-original-invitation-resend"))
	if err != nil {
		t.Fatal(err)
	}
	resendRequest := organization.InvitationResendOperationRequest{Authentication: owner.auth, IdempotencyKey: resendKey, OrganizationID: second.OrganizationID, InvitationID: sent.InvitationID, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "reconstructed-resend"}
	resendRecovered, err := invitationsOwner.Resend(ctx, resendRequest, "127.0.0.1")
	if err != nil || resendRecovered.Receipt.Outcome != identity.CommitOutcomeCommitted || resendRecovered.Receipt.Binding.CommandID != resent.CommandID || resendRecovered.Receipt.Feature == nil || resendRecovered.Receipt.Feature.BeforeVersion != 1 || resendRecovered.Receipt.Feature.AfterVersion != 2 || resendRecovered.DeliveryState != delivery.StateAccepted {
		t.Fatal("fresh Reference original resend recovery after acceptance", err)
	}
	cancelRequest := organization.InvitationCancelOperationRequest{Authentication: owner.auth, OrganizationID: third.OrganizationID, InvitationID: cancelSent.InvitationID, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "reconstructed-cancellation"}
	cancelRecovered, err := invitationsOwner.Cancel(ctx, cancelRequest, "127.0.0.1")
	if err != nil || cancelRecovered.Receipt.Outcome != identity.CommitOutcomeCommitted || cancelRecovered.Receipt.Binding.CommandID != cancelled.CommandID || cancelRecovered.Receipt.Feature == nil || cancelRecovered.Receipt.Feature.BeforeVersion != 1 || cancelRecovered.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("fresh Reference cancellation did not recover original history", err)
	}
	rejectRequest := organization.InvitationRejectOperationRequest{Authentication: recipient.auth, OrganizationID: fourth.OrganizationID, InvitationID: rejectSent.InvitationID, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "reconstructed-rejection"}
	rejectRecovered, err := invitationsOwner.Reject(ctx, rejectRequest, "127.0.0.1")
	if err != nil || rejectRecovered.Receipt.Outcome != identity.CommitOutcomeCommitted || rejectRecovered.Receipt.Binding.CommandID != rejected.CommandID || rejectRecovered.Receipt.Feature == nil || rejectRecovered.Receipt.Feature.BeforeVersion != 1 || rejectRecovered.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("fresh Reference rejection did not recover original history", err)
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, recipient.cookies, recipient.csrf, recipient.sessionID, f, features)
	if _, err := invitationsOwner.Reject(ctx, rejectRequest, "127.0.0.1"); err == nil {
		t.Fatal("revoked recipient recovered original rejection")
	}
	if code, _ := call(recipient, http.MethodPost, "/v1/organization/invitation/reject", rejectBody, ""); code == 200 {
		t.Fatal("revoked recipient repeated HTTP rejection")
	}
	if _, err := invitationsOwner.RecoverAccept(ctx, recovery); err == nil {
		t.Fatal("revoked recipient recovered protected history")
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, owner.cookies, owner.csrf, owner.sessionID, f, features)
	if code, _ := call(owner, http.MethodGet, "/v1/organization/get?organizationID="+string(second.OrganizationID), nil, ""); code == 200 {
		t.Fatal("revoked owner retained organization access")
	}
	if _, err := invitationsOwner.Resend(ctx, resendRequest, "127.0.0.1"); err == nil {
		t.Fatal("revoked manager recovered original resend")
	}
	if _, err := invitationsOwner.Cancel(ctx, cancelRequest, "127.0.0.1"); err == nil {
		t.Fatal("revoked manager recovered original cancellation")
	}
}

func commandIDForReference(t testing.TB) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type organizationTestHuman struct {
	auth       organization.Authentication
	user       identity.UserID
	identifier identity.IdentifierID
	sessionID  string
	cookies    []*http.Cookie
	csrf       string
}

func organizationHumanFromSession(t *testing.T, ctx context.Context, sessions reference.SessionService, cookies []*http.Cookie, csrf string) organizationTestHuman {
	t.Helper()
	if len(cookies) != 1 {
		t.Fatal("genuine session cookie absent")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("issued session rejected")
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !result.Authenticated || result.ValidateAt(time.Now()) != nil {
		t.Fatal("genuine session no longer current", err)
	}
	binding, err := result.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return organizationTestHuman{auth: organization.Authentication{TenantID: otpTenant, Bearer: auth.NewBearerCredential(cookies[0].Value)}, user: binding.UserID, sessionID: binding.SessionID, cookies: cookies, csrf: csrf}
}
func registerReferenceOrganizationHuman(t *testing.T, ctx context.Context, client *http.Client, base, origin string, features reference.FeatureSet, workers reference.WorkerSet, messages <-chan string) organizationTestHuman {
	t.Helper()
	post := func(path string, value any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(value)
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
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("genuine recipient request", err)
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if response.StatusCode != 200 || e != nil || closed != nil || len(body) > 16384 {
			t.Fatal("genuine recipient operation", path, response.StatusCode)
		}
		return response, body
	}
	issue := func(method string) (sessionhttp.PreAuthResponse, []*http.Cookie) {
		t.Helper()
		r, wire := post("/v1/session/preauth-issue", map[string]string{"method": method}, "", nil)
		var out sessionhttp.PreAuthResponse
		if json.Unmarshal(wire, &out) != nil || !out.Issued {
			t.Fatal("genuine recipient flow")
		}
		return out, r.Cookies()
	}
	flow, cookies := issue("signup")
	_, wire := post("/v1/password/signup", map[string]any{"flowID": flow.FlowID, "email": "organization-recipient@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/confirm"}, "reference-recipient-signup", cookies)
	var registered passwordhttp.SignupResponse
	if json.Unmarshal(wire, &registered) != nil || !registered.VerificationRequired || registered.CommitOutcome != "committed" {
		t.Fatal("genuine recipient signup")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("recipient verification absent")
	}
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatal("recipient verification link")
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	_, wire = post("/v1/email/verification-confirm", map[string]string{"token": u.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(id)}, "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if json.Unmarshal(wire, &confirmed) != nil || !confirmed.Confirmed || confirmed.Address == nil {
		t.Fatal("genuine recipient verification")
	}
	flow, cookies = issue("password")
	response, wire := post("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "organization-recipient@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, "", cookies)
	var signed passwordhttp.SigninResponse
	if json.Unmarshal(wire, &signed) != nil || !signed.SignedIn {
		t.Fatal("genuine recipient signin")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, sessions, response.Cookies(), response.Header.Get("X-CSRF-Token"))
	human.identifier = confirmed.Address.IdentifierID
	if human.user != confirmed.Address.UserID {
		t.Fatal("recipient identity binding changed")
	}
	return human
}
