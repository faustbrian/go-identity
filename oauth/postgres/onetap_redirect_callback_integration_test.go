//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// Observe the actual external velocity-store command, not a synthetic phase's
// request property. All native risk evaluation and evidence remain real.
type oneTapRedirectObservedCounters struct {
	boundary oneTapStartCounterBoundary
	commands []risk.CounterBinding
	preparer risk.CounterCoordinator
}

func (o *oneTapRedirectObservedCounters) Mutate(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
	o.commands = append(o.commands, command.Bindings())
	return o.boundary.Mutate(ctx, command)
}

func oneTapRedirectObservedRisk(t *testing.T, pool *database.Pool, original risk.AuthenticationAdmissionCustodyConfig, observer *oneTapRedirectObservedCounters) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{78}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counted, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: observer, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	observer.preparer = counted
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: 2 * time.Second, Counters: &counted,
		Sources: []risk.Source{{Name: "status", Version: "onetap-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
		}}}, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: oneTapStartPolicy, Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
			_, err := sink.Append(ctx, lost.Record())
			return err
		}}})
	if err != nil {
		t.Fatal(err)
	}
	original.Evaluation = evaluation
	return original
}

func oneTapRedirectCallbackFixture(t *testing.T) (context.Context, *database.Pool, *OneTapStartService, *OneTapCompletionService, *OneTapStartService, OneTapCompletionConfig, *rsa.PrivateKey, *oneTapRedirectObservedCounters) {
	t.Helper()
	ctx, pool, popup, _, completionConfig, signing := oneTapNativeCallbackFixture(t)
	c := oneTapRedirectStartConfig(popup.config())
	// Restore the fixture's original key configuration, which the public owner
	// deliberately does not retain in its runtime configuration projection.
	c.EnvelopeKeys = map[string][]byte{"onetap": bytes.Repeat([]byte{77}, 32)}
	c.Capability.RetainedReplayKeys = map[uint32][32]byte{1: {74}}
	c.CapabilityPreparation = capabilitypg.IssuancePreparationConfig{Deployment: "onetap-deployment", ActiveEnvelopeKey: "checkpoint", EnvelopeKeys: map[string][]byte{"checkpoint": bytes.Repeat([]byte{75}, 32)}, VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "onetap-signing", HMAC: bytes.Repeat([]byte{72}, 32)}}, Clock: time.Now}
	observer := &oneTapRedirectObservedCounters{}
	c.Risk = oneTapRedirectObservedRisk(t, pool, c.Risk, observer)
	start, err := NewOneTapRedirectStartService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	completionConfig.HostedDomain = "workspace.example"
	completion, err := NewOneTapRedirectCompletionService(start, completionConfig)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, start, completion, popup, completionConfig, signing, observer
}

func oneTapRedirectGoogleCredential(t *testing.T, key *rsa.PrivateKey, launch onetap.BrowserRedirectStartProjection, alter func(map[string]any)) []byte {
	t.Helper()
	now := time.Now().UTC()
	claims := map[string]any{"iss": "https://accounts.google.com", "sub": "opaque-google-subject", "aud": launch.ClientID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": launch.Nonce, "hd": "workspace.example"}
	if alter != nil {
		alter(claims)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"native-test"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(message + "." + base64.RawURLEncoding.EncodeToString(signature))
}

func oneTapRedirectCallbackRequest(t *testing.T, ctx context.Context, start *OneTapStartService, signing *rsa.PrivateKey, key string) (onetap.BrowserStartRequestSpec, OneTapRedirectBrowserStart, OneTapRedirectCallbackRequest) {
	t.Helper()
	spec, request := oneTapRedirectStartRequest(t, key)
	spec.Device = "original-sealed-redirect-device"
	request, err := onetap.NewBrowserRedirectStartRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	result, err := start.StartRedirect(ctx, request)
	browser, ok := result.RedirectBrowser()
	if err != nil || !ok {
		t.Fatal("start real redirect flow", err)
	}
	token, err := browser.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return spec, browser, OneTapRedirectCallbackRequest{FlowID: identity.PreAuthTransactionID(browser.Projection.State), FlowCookie: auth.NewBearerCredential(token), Network: netip.MustParseAddr("192.0.2.81"),
		Callback: onetap.Callback{Origin: spec.Origin, Redirect: browser.Projection.LoginURI, CSRFCookies: []string{"gis-redirect-csrf"}, CSRFBody: []string{"gis-redirect-csrf"}, Credential: oauth.GoogleCredential{IDToken: oneTapRedirectGoogleCredential(t, signing, browser.Projection, nil)}}}
}

func TestOneTapRedirectCallbackCommitsSessionWithRetainedDeviceRiskAndRecovery(t *testing.T) {
	ctx, pool, start, completion, popup, config, signing, observed := oneTapRedirectCallbackFixture(t)
	spec, browser, request := oneTapRedirectCallbackRequest(t, ctx, start, signing, "redirect-callback-success")
	if _, exists := reflect.TypeFor[OneTapRedirectCallbackRequest]().FieldByName("Device"); exists {
		t.Fatal("redirect callback admits a browser-selected device")
	}
	if service, err := NewOneTapCompletionService(start, config); err == nil || service != nil {
		t.Fatal("popup constructor accepted redirect start")
	}
	if service, err := NewOneTapRedirectCompletionService(popup, config); err == nil || service != nil {
		t.Fatal("redirect constructor accepted popup start")
	}
	wrongMode, err := completion.Callback(ctx, OneTapCallbackRequest{})
	if err == nil {
		t.Fatal("popup Callback accepted redirect completion")
	}
	oneTapNativeCallbackNoDelivery(t, wrongMode)
	_, original, _, err := start.readOneTapCallbackBrowser(ctx, request.FlowID, request.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	result, err := completion.RedirectCallback(ctx, request)
	if err != nil || result.Session.CommitOutcome != identity.CommitOutcomeCommitted || result.Session.Replayed {
		t.Fatal("redirect callback did not freshly commit", result.Session.CommitOutcome, err)
	}
	sessionSpec, err := result.Session.Session.Bindings()
	if err != nil || sessionSpec.UserID != "onetap-user" || sessionSpec.Remember != spec.Remember || sessionSpec.Authentication.CredentialID != "google-credential" || sessionSpec.Authentication.ProofVersion != 7 || result.Session.DeliveryValidUntil.After(browser.Projection.ExpiresAt) {
		t.Fatal("redirect session lost original identity, lifetime or delivery cutoff", err)
	}
	bearer, err := result.Session.Token.Reveal()
	if err != nil || bearer == request.FlowCookie.Token() {
		t.Fatal("redirect did not issue an independent session bearer", err)
	}
	csrf, err := result.CSRF.Reveal()
	if err != nil || csrf == bearer {
		t.Fatal("redirect did not issue independent CSRF", err)
	}
	parsed, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.Digest(config.Issuer.LookupKey, string(sessionSpec.TenantID))
	if err != nil || digest != sessionSpec.Lookup {
		t.Fatal("redirect bearer did not match stored lookup", err)
	}
	csrfToken, err := session.ParseCSRFToken(csrf)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewRepository(pool, start.config().Session)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := reader.Get(ctx, sessionSpec.TenantID, sessionSpec.SessionID)
	if err != nil || stored.Revoked || stored.Session.CSRFState().Check(session.CSRFBinding{TenantID: sessionSpec.TenantID, SessionID: sessionSpec.SessionID, SessionVersion: sessionSpec.Version}, csrfToken, config.CSRF) != nil {
		t.Fatal("redirect session/CSRF not durably active", err)
	}
	var actual *risk.CounterBinding
	for i := range observed.commands {
		if observed.commands[i].Operation == risk.Action(oneTapCallbackPurpose) && observed.commands[i].Attempt == string(result.Session.CommandID) {
			if actual != nil {
				t.Fatal("callback risk charged twice")
			}
			actual = &observed.commands[i]
		}
	}
	if actual == nil {
		t.Fatal("native callback did not dispatch its actual bound risk attempt")
	}
	intentKey := start.config().IntentKey
	mac := hmac.New(sha256.New, intentKey[:])
	_, _ = mac.Write([]byte("identity-onetap-callback-risk-v1\x00"))
	_, _ = mac.Write(completion.profile[:])
	expected, err := observed.preparer.Prepare(risk.Context{Tenant: string(start.config().TenantID), Operation: risk.Action(oneTapCallbackPurpose), Attempt: actual.Attempt}, risk.Subject{Network: request.Network.String(), Device: spec.Device, IdentifierDigest: hex.EncodeToString(mac.Sum(nil))}, risk.BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	deviceTarget := func(b risk.CounterBinding) []risk.CounterKey {
		for _, target := range b.Targets {
			if target.Dimension == risk.DeviceDimension {
				return target.Keys
			}
		}
		return nil
	}
	if len(deviceTarget(*actual)) == 0 || !reflect.DeepEqual(deviceTarget(*actual), deviceTarget(expected.Bindings())) {
		t.Fatal("actual counted callback did not use the original sealed device")
	}
	oneTapNativeCallbackState(t, ctx, pool, request.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, true)
	replay, _ := completion.RedirectCallback(ctx, request)
	oneTapNativeCallbackNoDelivery(t, replay)
	q := identity.RecoveryQuery{CommandID: result.Session.CommandID, TenantID: start.config().TenantID, ActorID: start.config().Issuance.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: oneTapCallbackPurpose, RecordID: string(request.FlowID), AnonymousFlowID: string(request.FlowID)}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{ID: oneTapStartActor, Kind: authorization.SubjectServiceAccount}, Tenant: oneTapStartTenant, Action: oneTapCallbackPurpose, Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(request.FlowID)}}}
	recovered, err := completion.RecoverCallback(ctx, q, caller)
	if err != nil || recovered.CommandID != result.Session.CommandID || recovered.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("redirect recovery lost original receipt", err)
	}
	oneTapNativeCallbackNoDelivery(t, OneTapCallbackResult{Session: recovered})
}

func TestOneTapRedirectCallbackRejectsSubstitutionAndInvalidProofWithoutEffects(t *testing.T) {
	ctx, pool, start, completion, popup, config, signing, observed := oneTapRedirectCallbackFixture(t)
	_, _, foreign := oneTapRedirectCallbackRequest(t, ctx, start, signing, "redirect-foreign")
	_, popupRequest := oneTapNativeCallbackRequest(t, ctx, popup, signing, "redirect-popup-original")
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*OneTapRedirectCallbackRequest, onetap.BrowserRedirectStartProjection)
	}{
		{"endpoint", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Callback.Redirect += "/other"
		}},
		{"origin", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Callback.Origin = "https://foreign.example"
		}},
		{"cookie", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.FlowCookie = foreign.FlowCookie
		}},
		{"popup mode", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.FlowID = popupRequest.FlowID
			r.FlowCookie = popupRequest.FlowCookie
		}},
		{"csrf", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Callback.CSRFBody = []string{"other-csrf"}
		}},
		{"duplicate csrf", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Callback.CSRFCookies = append(r.Callback.CSRFCookies, "another")
		}},
		{"noncanonical csrf", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Callback.CSRFCookies, r.Callback.CSRFBody = []string{"same invalid csrf"}, []string{"same invalid csrf"}
		}},
		{"credential bound", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Callback.Credential.IDToken = bytes.Repeat([]byte{'a'}, start.config().Provider.Profile().MaxTokenBytes+1)
		}},
		{"missing network", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Network = netip.Addr{}
		}},
		{"multicast network", func(r *OneTapRedirectCallbackRequest, _ onetap.BrowserRedirectStartProjection) {
			r.Network = netip.MustParseAddr("224.0.0.1")
		}},
		{"signature", func(r *OneTapRedirectCallbackRequest, p onetap.BrowserRedirectStartProjection) {
			r.Callback.Credential.IDToken = oneTapRedirectGoogleCredential(t, foreignKey, p, nil)
		}},
		{"nonce", func(r *OneTapRedirectCallbackRequest, p onetap.BrowserRedirectStartProjection) {
			r.Callback.Credential.IDToken = oneTapRedirectGoogleCredential(t, signing, p, func(c map[string]any) { c["nonce"] = "wrong" })
		}},
		{"hosted domain", func(r *OneTapRedirectCallbackRequest, p onetap.BrowserRedirectStartProjection) {
			r.Callback.Credential.IDToken = oneTapRedirectGoogleCredential(t, signing, p, func(c map[string]any) { c["hd"] = "other.example" })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, browser, request := oneTapRedirectCallbackRequest(t, ctx, start, signing, "redirect-denied-"+strings.ReplaceAll(tc.name, " ", "-"))
			_, original, _, err := start.readOneTapCallbackBrowser(ctx, request.FlowID, request.FlowCookie, config.FlowKeys)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := start.loadOneTapCallbackGrant(ctx, original)
			if err != nil {
				t.Fatal(err)
			}
			defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			originalID := request.FlowID
			tc.change(&request, browser.Projection)
			before := len(observed.commands)
			result, err := completion.RedirectCallback(ctx, request)
			if err == nil || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid redirect callback committed", err)
			}
			oneTapNativeCallbackNoDelivery(t, result)
			if tc.name != "signature" && tc.name != "nonce" && tc.name != "hosted domain" && len(observed.commands) != before {
				t.Fatal("unbound browser context reached counted retained-device risk")
			}
			oneTapNativeCallbackState(t, ctx, pool, originalID, grant.Grant.CapabilityID, result.Session.CommandID, false)
		})
	}
}

func TestOneTapRedirectCallbackRollsBackProtectedEffectsAtCommit(t *testing.T) {
	ctx, pool, start, completion, _, config, signing, _ := oneTapRedirectCallbackFixture(t)
	_, _, request := oneTapRedirectCallbackRequest(t, ctx, start, signing, "redirect-callback-rollback")
	_, original, _, err := start.readOneTapCallbackBrowser(ctx, request.FlowID, request.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	if _, err := pool.Raw().Exec(ctx, `CREATE SEQUENCE onetap_sessions.redirect_callback_commit_observed;
CREATE FUNCTION onetap_sessions.reject_redirect_callback_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
PERFORM nextval('onetap_sessions.redirect_callback_commit_observed');
RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='fixture requested callback abort'; END $$;
CREATE CONSTRAINT TRIGGER reject_redirect_callback_commit AFTER INSERT ON onetap_sessions.session_issuances
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION onetap_sessions.reject_redirect_callback_commit()`); err != nil {
		t.Fatal(err)
	}
	result, err := completion.RedirectCallback(ctx, request)
	if err == nil || result.Session.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("failed redirect COMMIT reported success", err)
	}
	oneTapNativeCallbackNoDelivery(t, result)
	var reached bool
	if err := pool.Raw().QueryRow(ctx, `SELECT is_called FROM onetap_sessions.redirect_callback_commit_observed`).Scan(&reached); err != nil || !reached {
		t.Fatal("redirect callback did not reach deferred COMMIT", err)
	}
	oneTapNativeCallbackState(t, ctx, pool, request.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, false)
}

func TestOneTapRedirectCallbackRequiresExactSealedDeviceAndPopupAbsence(t *testing.T) {
	ctx, pool, start, completion, popup, config, signing, observed := oneTapRedirectCallbackFixture(t)
	_, _, request := oneTapRedirectCallbackRequest(t, ctx, start, signing, "redirect-sealed-device")
	_, original, _, err := start.readOneTapCallbackBrowser(ctx, request.FlowID, request.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := start.loadOneTapCallbackGrant(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	flow, _ := base64.RawURLEncoding.DecodeString(string(request.FlowID))
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT proof_ciphertext FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, oneTapStartTenant, flow).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	aad, err := start.callbackAAD(grant.Original, original.Transaction.Binding.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	var sealed oneTapStoredCallbackGrant
	if err := start.openOneTap(ctx, aad, ciphertext, 65536, &sealed); err != nil {
		t.Fatal(err)
	}
	defer clear(sealed.Proof)
	before := len(observed.commands)
	for _, device := range []string{"", "bad device", strings.Repeat("x", 129)} {
		sealed.Device = device
		wire, err := start.sealOneTap(ctx, aad, sealed, 65536)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=$3 WHERE tenant_id=$1 AND flow_id=$2`, oneTapStartTenant, flow, wire); err != nil {
			t.Fatal(err)
		}
		result, err := completion.RedirectCallback(ctx, request)
		if err == nil || len(observed.commands) != before {
			t.Fatal("invalid sealed device reached risk or completed", err)
		}
		oneTapNativeCallbackNoDelivery(t, result)
		oneTapNativeCallbackState(t, ctx, pool, request.FlowID, grant.Grant.CapabilityID, result.Session.CommandID, false)
	}
	popupFlow, popupRequest := oneTapNativeCallbackRequest(t, ctx, popup, signing, "popup-retained-device-forbidden")
	_, popupOriginal, _, err := popup.readOneTapCallbackBrowser(ctx, popupFlow.FlowID, popupRequest.FlowCookie, config.FlowKeys)
	if err != nil {
		t.Fatal(err)
	}
	popupGrant, err := popup.loadOneTapCallbackGrant(ctx, popupOriginal)
	if err != nil {
		t.Fatal(err)
	}
	defer popupGrant.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
	popupAAD, err := popup.callbackAAD(popupGrant.Original, popupFlow.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	popupID, _ := base64.RawURLEncoding.DecodeString(string(popupFlow.FlowID))
	if err := pool.Raw().QueryRow(ctx, `SELECT proof_ciphertext FROM onetap_oauth.onetap_callback_grants WHERE tenant_id=$1 AND flow_id=$2`, oneTapStartTenant, popupID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if err := popup.openOneTap(ctx, popupAAD, ciphertext, 65536, &sealed); err != nil {
		t.Fatal(err)
	}
	sealed.Device = "not-present-in-popup"
	wire, err := popup.sealOneTap(ctx, popupAAD, sealed, 65536)
	if err != nil {
		t.Fatal(err)
	}
	clear(sealed.Proof)
	if _, err := pool.Raw().Exec(ctx, `UPDATE onetap_oauth.onetap_callback_grants SET proof_ciphertext=$3 WHERE tenant_id=$1 AND flow_id=$2`, oneTapStartTenant, popupID, wire); err != nil {
		t.Fatal(err)
	}
	if got, err := popup.loadOneTapCallbackGrant(ctx, popupOriginal); err == nil {
		_ = got.Proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		t.Fatal("popup grant accepted retained redirect device")
	}
}
