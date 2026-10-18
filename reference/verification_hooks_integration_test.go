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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresVerificationHooks(t *testing.T) {
	for _, mode := range []string{"allow", "reject", "before-error", "after-error", "rollback", "unknown", "late-authority", "managed-allow", "managed-after-error", "allow-http", "after-error-http"} {
		t.Run(mode, func(t *testing.T) {
			extensions := signupGraphExtensions{postgresBaseline: true, verificationHooks: mode, completionCommitFault: mode == "unknown"}
			if strings.HasPrefix(mode, "managed-") {
				extensions.emailManagementResend, extensions.emailChangeCase = true, "graph"
			}
			proveReferenceSignupGraphExtensions(t, false, extensions)
		})
	}
}

type referenceVerificationHooks struct {
	t             *testing.T
	f             liveStores
	mode          string
	before, after atomic.Int32
}

func configureReferenceVerificationHooks(t *testing.T, c *reference.StoreConfiguration, f liveStores, mode string) *referenceVerificationHooks {
	t.Helper()
	h := &referenceVerificationHooks{t: t, f: f, mode: mode}
	selection, err := email.NewVerificationHooks([]identity.Hook{h}, email.VerificationHooksConfig{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(mode, "managed-") {
		c.Email.Verification.Native.VerificationHooks = selection
		c.Email.Verification.Native.ConfigurationID = "reference-managed-hooks-v1"
	} else {
		c.PasswordSignup.Native.Verification.Hooks = selection
		c.PasswordSignup.Native.ConfigurationID = "reference-signup-hooks-v1"
	}
	return h
}

func (h *referenceVerificationHooks) Before(ctx context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
	h.before.Add(1)
	if in.Context.OperationID != "identity.email.verification-confirm" || in.Context.TenantID != otpTenant || in.Context.Deadline.IsZero() || len(in.Fields) != 3 {
		h.t.Fatal("incorrect verification callback metadata")
	}
	var command, user, address string
	for _, field := range in.Fields {
		if field.Sensitivity != identity.SensitivitySensitive || field.Value.Kind != identity.AttributeString {
			h.t.Fatal("unsafe callback metadata")
		}
		switch field.Name {
		case "command_id":
			command = field.Value.String
		case "user_id":
			user = field.Value.String
		case "identifier_id":
			address = field.Value.String
		default:
			h.t.Fatal("unregistered callback field")
		}
	}
	key, err := base64.RawURLEncoding.DecodeString(command)
	if err != nil {
		return identity.BeforeHookResult{}, err
	}
	var claimed, verified bool
	if err := h.f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.commands WHERE command_id=$1), EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$2 AND user_id=$3 AND identifier_id=$4 AND verified)`, key, otpTenant, user, address).Scan(&claimed, &verified); err != nil {
		return identity.BeforeHookResult{}, err
	}
	if claimed || verified {
		h.t.Fatal("before hook ran after reservation or verification")
	}
	if h.mode == "late-authority" {
		if _, err := h.f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, user); err != nil {
			return identity.BeforeHookResult{}, err
		}
	}
	if h.mode == "reject" {
		return identity.BeforeHookResult{Decision: identity.BeforeHookReject}, nil
	}
	if h.mode == "before-error" {
		return identity.BeforeHookResult{}, errors.New("private callback diagnostic")
	}
	return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
}

func (h *referenceVerificationHooks) After(ctx context.Context, in identity.AfterHookInput) error {
	h.after.Add(1)
	if in.Observation.Outcome != identity.AttemptedCommitOutcomeCommitted {
		h.t.Fatal("observer received noncommit")
	}
	// A separate connection sees the final row only after protected SQL closes.
	// Merely invoking After before COMMIT cannot satisfy this assertion.
	var verified int
	if err := h.f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND verified`, otpTenant).Scan(&verified); err != nil {
		return err
	}
	wantVerified := 1
	if strings.HasPrefix(h.mode, "managed-") {
		wantVerified = 2
	}
	if verified != wantVerified {
		h.t.Fatal("observer ran before committed verification became visible")
	}
	if strings.Contains(h.mode, "after-error") {
		return errors.New("private observer diagnostic")
	}
	return nil
}

func proveManagedVerificationHooks(t *testing.T, ctx context.Context, features reference.FeatureSet, hooks *referenceVerificationHooks, request email.VerificationConfirmRequest) {
	t.Helper()
	if hooks.before.Load() != 0 || hooks.after.Load() != 0 {
		t.Fatal("scanner or superseded proof invoked hooks")
	}
	owner, err := features.EmailVerification()
	if err != nil {
		t.Fatal(err)
	}
	out, executionErr := owner.VerificationConfirm(ctx, request)
	if out.Outcome != identity.CommitOutcomeCommitted || hooks.before.Load() != 1 || hooks.after.Load() != 1 {
		t.Fatal("managed verification hooks not composed", out.Outcome, executionErr)
	}
	if hooks.mode == "managed-after-error" {
		if executionErr == nil || out.Address != (identity.IdentifierProjection{}) || strings.Contains(executionErr.Error(), "private") {
			t.Fatal("managed observer failure lost commit/redaction")
		}
	} else if executionErr != nil || out.Address == (identity.IdentifierProjection{}) {
		t.Fatal("managed fresh verification missing", executionErr)
	}
	replayed, err := owner.VerificationConfirm(ctx, request)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Address != (identity.IdentifierProjection{}) {
		t.Fatal("managed replay changed outcome/disclosure", err)
	}
	recovered, err := owner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: out.Recovery, Caller: request.Caller})
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || hooks.before.Load() != 1 || hooks.after.Load() != 1 {
		t.Fatal("managed metadata recovery repeated callbacks", err)
	}
}

func proveReferenceVerificationHooks(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, hooks *referenceVerificationHooks) {
	t.Helper()
	post := func(path string, body any, key string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded or cacheable response")
		}
		return response, payload
	}
	r, wire := post("/v1/session/preauth-issue", map[string]string{"method": "signup"}, "", nil)
	var flow sessionhttp.PreAuthResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &flow) != nil || !flow.Issued {
		t.Fatal("original signup initiation", r.StatusCode)
	}
	r, wire = post("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": "verification-hooks@example.invalid", "password": "synthetic-verification-password", "callbackURL": origin + "/confirm"}, "verification-hooks-original", r.Cookies())
	var signup passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(wire, &signup) != nil || signup.CommitOutcome != "committed" || !signup.VerificationRequired {
		t.Fatal("genuine signup", r.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("missing actual delivery")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(u.Query().Get("token"), capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	callback, _ := url.Parse(origin + "/confirm")
	id, _ := identity.NewCommandID()
	caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: string(id), Request: authorization.Request{Tenant: otpTenant, Action: "identity.email.verification-confirm", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Resource: authorization.Resource{Type: "identity.user"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	owner, err := features.RegistrationVerification()
	if err != nil {
		t.Fatal(err)
	}
	request := email.VerificationConfirmRequest{TenantID: otpTenant, CommandID: id, Token: proof, Callback: *callback, Network: "127.0.0.1", Caller: caller}
	if strings.HasSuffix(hooks.mode, "-http") {
		body := map[string]string{"token": u.Query().Get("token"), "callback": callback.String(), "commandID": string(id)}
		r, wire := post("/v1/email/verification-confirm", body, "", nil)
		var confirmed emailhttp.ConfirmationResponse
		if json.Unmarshal(wire, &confirmed) != nil || confirmed.CommitOutcome != "committed" || confirmed.Recovery == nil || hooks.before.Load() != 1 || hooks.after.Load() != 1 || len(r.Cookies()) != 0 || r.Header.Get("X-CSRF-Token") != "" || bytes.Contains(wire, []byte(body["token"])) || bytes.Contains(wire, []byte("private")) {
			t.Fatal("HTTP hook lost known commit or credential custody", r.StatusCode)
		}
		if hooks.mode == "after-error-http" {
			if r.StatusCode != http.StatusServiceUnavailable || confirmed.Address != nil {
				t.Fatal("HTTP observer failure disclosed projection or success", r.StatusCode)
			}
		} else if r.StatusCode != http.StatusOK || !confirmed.Confirmed || confirmed.Address == nil {
			t.Fatal("HTTP selected hook did not confirm", r.StatusCode)
		}
		r, wire = post("/v1/email/verification-confirm", body, "", nil)
		var replay emailhttp.ConfirmationResponse
		if r.StatusCode != http.StatusOK || json.Unmarshal(wire, &replay) != nil || replay.CommitOutcome != "committed" || !replay.Confirmed || !replay.Replayed || replay.Address != nil || hooks.before.Load() != 1 || hooks.after.Load() != 1 || len(r.Cookies()) != 0 {
			t.Fatal("HTTP replay repeated callbacks or disclosure", r.StatusCode)
		}
		var verified, consumed int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use)`).Scan(&verified, &consumed); err != nil || verified != 1 || consumed != 1 {
			t.Fatal("HTTP callback effects not durable", err)
		}
		return
	}
	if hooks.mode == "rollback" {
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.verification_hook_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic verification failure'; END $$; CREATE TRIGGER verification_hook_fail BEFORE INSERT ON identity.email_verifications FOR EACH ROW EXECUTE FUNCTION public.verification_hook_fail()`); err != nil {
			t.Fatal(err)
		}
	}
	if hooks.mode == "unknown" {
		f.completionFault.armed.Store(true)
	}
	out, executionErr := owner.VerificationConfirm(ctx, request)
	if hooks.mode == "unknown" {
		f.completionFault.armed.Store(false)
	}
	if hooks.before.Load() != 1 {
		t.Fatal("configured before hook missing or duplicated", hooks.before.Load())
	}
	if executionErr != nil && strings.Contains(executionErr.Error(), "private") {
		t.Fatal("callback error disclosed")
	}
	var verified, consumed, charges int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use),(SELECT count(*) FROM risk_store.counter_charges)`).Scan(&verified, &consumed, &charges); err != nil {
		t.Fatal(err)
	}
	if hooks.mode == "reject" || hooks.mode == "before-error" || hooks.mode == "late-authority" || hooks.mode == "rollback" {
		// The existing coordinator charges an admitted attempt in reservation,
		// before protected Work. Later rollback/authority denial must not erase
		// that anti-abuse debit; a hook rejection precedes reservation entirely.
		wantCharges := btoi(hooks.mode == "late-authority" || hooks.mode == "rollback")
		if executionErr == nil || out.Outcome == identity.CommitOutcomeCommitted || verified != 0 || consumed != 0 || charges != int(wantCharges) || hooks.after.Load() != 0 {
			t.Fatal("denial/rollback leaked effects or lost admitted charge", out.Outcome, verified, consumed, charges, executionErr)
		}
		return
	}
	if verified != 1 || consumed != 1 || charges != 1 {
		t.Fatal("verification effects not atomic")
	}
	if hooks.mode == "unknown" {
		if executionErr == nil || out.Outcome != identity.CommitOutcomeUnknown || !f.completionFault.hit.Load() || hooks.after.Load() != 0 {
			t.Fatal("lost commit acknowledgement invoked observer or hid ambiguity", out.Outcome)
		}
	} else {
		if out.Outcome != identity.CommitOutcomeCommitted || hooks.after.Load() != 1 {
			t.Fatal("known commit observer missing", out.Outcome, executionErr)
		}
		if hooks.mode == "after-error" {
			if executionErr == nil || out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("observer failure lost commit or disclosed projection")
			}
		} else if executionErr != nil || out.Address == (identity.IdentifierProjection{}) {
			t.Fatal("successful callback withheld fresh projection", executionErr)
		}
	}
	if out.Recovery == (email.VerificationRecovery{}) {
		t.Fatal("known/unknown result lost recovery")
	}
	replayed, err := owner.VerificationConfirm(ctx, request)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Address != (identity.IdentifierProjection{}) || hooks.before.Load() != 1 || hooks.after.Load() != btoi(hooks.mode != "unknown") {
		t.Fatal("replay repeated callbacks or disclosed projection", err)
	}
	recovered, err := owner.VerificationRecover(ctx, email.VerificationRecoveryRequest{Recovery: out.Recovery, Caller: caller})
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || hooks.before.Load() != 1 || hooks.after.Load() != btoi(hooks.mode != "unknown") {
		t.Fatal("metadata recovery repeated callbacks", err)
	}
}

func btoi(value bool) int32 {
	if value {
		return 1
	}
	return 0
}
