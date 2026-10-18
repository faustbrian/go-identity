//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresRemainingConfirmationHooks(t *testing.T) {
	for _, profile := range []string{"link", "otp-verify", "otp-change", "otp-initial", "totp-change", "link-http", "otp-verify-http", "otp-change-http"} {
		modes := []string{"allow"}
		if profile == "link" || profile == "otp-verify" || profile == "otp-change" {
			modes = append(modes, "reject", "before-error", "after-error", "late-authority")
		}
		if profile == "otp-verify" || profile == "otp-change" {
			modes = append(modes, "rollback", "unknown", "wrong-reject", "wrong-before-error")
		}
		if profile == "otp-verify-http" || profile == "otp-change-http" {
			modes = append(modes, "after-error")
		}
		for _, mode := range modes {
			t.Run(profile+"/"+mode, func(t *testing.T) {
				x := signupGraphExtensions{postgresBaseline: true, confirmationHooks: profile + "/" + mode}
				switch profile {
				case "otp-verify":
					x.emailManagementResend, x.emailChangeCase = true, "otp-verification"
				case "otp-change", "otp-initial":
					x.emailManagementChange, x.emailChangeCase = true, "otp-change"
					x.emailOTPInitialPrimary = profile == "otp-initial"
				case "totp-change":
					x.emailManagementChange, x.emailChangeCase = true, "totp-change"
					x.mfaEnrollment, x.activeStepUp, x.passwordRecovery = true, true, true
				default:
					x.emailManagementChange, x.emailChangeCase = true, "graph"
				}
				switch profile {
				case "link-http":
					x.emailChangeCase = "request-http"
				case "otp-verify-http":
					x.emailManagementChange, x.emailManagementResend, x.emailChangeCase = false, true, "otp-verification-reference-https"
				case "otp-change-http":
					x.emailChangeCase = "otp-change-reference-https"
				}
				if mode == "rollback" || mode == "unknown" {
					x.emailChangeCase += "-" + mode
					x.completionCommitFault = mode == "unknown"
				}
				proveReferenceSignupGraphExtensions(t, false, x, profile == "totp-change")
			})
		}
	}
}

type confirmationHookProbe struct {
	lastCommand              string
	t                        *testing.T
	f                        liveStores
	profile, mode, operation string
	before, after            atomic.Int32
	mu                       sync.Mutex
	targets                  map[string][2]string
}

func configureRemainingConfirmationHooks(t *testing.T, c *reference.StoreConfiguration, f liveStores, selected string) *confirmationHookProbe {
	t.Helper()
	profile, mode, _ := strings.Cut(selected, "/")
	profile = strings.TrimSuffix(profile, "-http")
	h := &confirmationHookProbe{t: t, f: f, profile: profile, mode: mode, operation: "identity.email.change-confirm", targets: make(map[string][2]string)}
	if profile == "otp-verify" {
		h.operation = "identity.otp.email-verify"
	} else if profile == "otp-change" || profile == "otp-initial" {
		h.operation = "identity.otp.email-change-confirm"
	}
	selection, err := email.NewVerificationHooks([]identity.Hook{h}, email.VerificationHooksConfig{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	switch profile {
	case "otp-verify":
		c.Email.OTPVerification.VerificationHooks = selection
	case "otp-change", "otp-initial":
		c.Email.OTPChange.VerificationHooks = selection
	default:
		c.Email.Change.Native.ChangeHooks = selection
		c.Email.Change.Native.ConfigurationID = "reference-change-hooks-v1"
	}
	t.Cleanup(func() {
		want := int32(1)
		if profile == "link" || profile == "totp-change" {
			// This maintained journey establishes a primary, then replaces it.
			want = 2
		}
		if strings.HasSuffix(mode, "reject") || strings.HasSuffix(mode, "before-error") || mode == "late-authority" || mode == "rollback" || mode == "unknown" {
			want = 0
		}
		if h.before.Load() == 0 || h.after.Load() != want {
			t.Error("confirmation hooks absent or wrong success/history placement", h.before.Load(), h.after.Load())
		}
	})
	return h
}

func (h *confirmationHookProbe) special() bool {
	return strings.HasSuffix(h.mode, "reject") || strings.HasSuffix(h.mode, "before-error") || h.mode == "after-error" || h.mode == "late-authority"
}

func (h *confirmationHookProbe) Before(ctx context.Context, in identity.BeforeHookInput) (identity.BeforeHookResult, error) {
	h.before.Add(1)
	if in.Context.OperationID != h.operation || in.Context.TenantID != otpTenant || in.Context.Deadline.IsZero() || len(in.Fields) != 3 {
		h.t.Fatal("incorrect confirmation hook scope")
	}
	var command string
	var target [2]string
	for _, field := range in.Fields {
		if field.Value.Kind != identity.AttributeString || field.Sensitivity != identity.SensitivitySensitive {
			h.t.Fatal("unsafe confirmation hook metadata")
		}
		switch field.Name {
		case "command_id":
			command = field.Value.String
		case "user_id":
			target[0] = field.Value.String
		case "identifier_id":
			target[1] = field.Value.String
		default:
			h.t.Fatal("unregistered confirmation hook metadata")
		}
	}
	key, err := base64.RawURLEncoding.DecodeString(command)
	if err != nil {
		return identity.BeforeHookResult{}, err
	}
	var claimed bool
	if err := h.f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.commands WHERE command_id=$1)`, key).Scan(&claimed); err != nil {
		return identity.BeforeHookResult{}, err
	}
	if claimed {
		h.t.Fatal("before hook ran after reservation")
	}
	if err := h.inspectTarget(ctx, target, false); err != nil {
		return identity.BeforeHookResult{}, err
	}
	h.mu.Lock()
	h.targets[in.Context.CorrelationID] = target
	h.lastCommand = command
	h.mu.Unlock()
	if strings.HasSuffix(h.mode, "reject") {
		return identity.BeforeHookResult{Decision: identity.BeforeHookReject}, nil
	}
	if strings.HasSuffix(h.mode, "before-error") {
		return identity.BeforeHookResult{}, errors.New("private confirmation diagnostic")
	}
	if h.mode == "late-authority" {
		if _, err := h.f.pool.Raw().Exec(ctx, `UPDATE identity.users SET authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, target[0]); err != nil {
			return identity.BeforeHookResult{}, err
		}
	}
	return identity.BeforeHookResult{Decision: identity.BeforeHookContinue}, nil
}

// NOWAIT on a separate connection challenges transaction placement, rather than
// allowing an ordinary MVCC read to conceal a callback under protected locks.
func (h *confirmationHookProbe) inspectTarget(ctx context.Context, target [2]string, committed bool) error {
	tx, err := h.f.pool.Raw().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var verified, primary bool
	if err := tx.QueryRow(ctx, `SELECT verified,is_primary FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 FOR UPDATE NOWAIT`, otpTenant, target[0], target[1]).Scan(&verified, &primary); err != nil {
		return err
	}
	if verified != committed || primary != (committed && h.profile != "otp-verify") {
		h.t.Fatal("callback did not observe expected durable identifier transition")
	}
	return tx.Commit(ctx)
}

func (h *confirmationHookProbe) After(ctx context.Context, in identity.AfterHookInput) error {
	h.after.Add(1)
	if in.Context.OperationID != h.operation || in.Observation.Outcome != identity.AttemptedCommitOutcomeCommitted {
		h.t.Fatal("wrong success observation")
	}
	h.mu.Lock()
	target, exists := h.targets[in.Context.CorrelationID]
	h.mu.Unlock()
	if !exists {
		h.t.Fatal("observer lost exact original correlation")
	}
	if err := h.inspectTarget(ctx, target, true); err != nil {
		return err
	}
	if h.mode == "after-error" {
		return errors.New("private confirmation diagnostic")
	}
	return nil
}

type confirmationHookResult struct {
	outcome identity.CommitOutcome
	address identity.IdentifierProjection
	err     error
	recover func() (identity.CommitOutcome, identity.IdentifierProjection, error)
}

func proveConfirmationHookOutcome(t *testing.T, ctx context.Context, f liveStores, user identity.UserID, address identity.IdentifierID, invoke func() confirmationHookResult, readSession func([]*http.Cookie) bool, cookies []*http.Cookie, otpCommand identity.CommandID) bool {
	t.Helper()
	h := f.confirmationHooks
	if h.before.Load() != h.after.Load() {
		t.Fatal("send/scanner invoked confirmation hooks")
	}
	var notices int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	var challengeVersion string
	if otpCommand != "" {
		if err := f.pool.Raw().QueryRow(ctx, `SELECT version::text FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(otpCommand)).Scan(&challengeVersion); err != nil {
			t.Fatal(err)
		}
	}
	out := invoke()
	if out.err == nil || strings.Contains(out.err.Error(), "private") || out.address != (identity.IdentifierProjection{}) {
		t.Fatal("callback failure was ignored or disclosed confidential data", out.err)
	}
	wantCommitted := h.mode == "after-error"
	if (out.outcome == identity.CommitOutcomeCommitted) != wantCommitted {
		t.Fatal("callback error corrupted durable outcome", out.outcome)
	}
	if err := h.inspectTarget(ctx, [2]string{string(user), string(address)}, wantCommitted); err != nil {
		t.Fatal(err)
	}
	if otpCommand != "" {
		var used, failed int
		var version string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts,version::text FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(otpCommand)).Scan(&used, &failed, &version); err != nil {
			t.Fatal(err)
		}
		want := 0
		if wantCommitted {
			want = 1
		}
		if used != want || failed != 0 || !wantCommitted && version != challengeVersion {
			t.Fatal("hook veto or observer changed OTP attempt accounting", used)
		}
	}
	if strings.HasSuffix(h.mode, "reject") || strings.HasSuffix(h.mode, "before-error") {
		h.mu.Lock()
		command := h.lastCommand
		h.mu.Unlock()
		key, err := base64.RawURLEncoding.DecodeString(command)
		if err != nil {
			t.Fatal(err)
		}
		var claims int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, key).Scan(&claims); err != nil || claims != 0 {
			t.Fatal("hook veto persisted a command claim", err)
		}
	}
	var afterNotices int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&afterNotices); err != nil {
		t.Fatal(err)
	}
	wantNotices := notices
	if wantCommitted && h.profile != "otp-verify" {
		wantNotices++
	}
	if afterNotices != wantNotices {
		t.Fatal("hook failure changed atomic notice effects")
	}
	if h.mode != "late-authority" && readSession(cookies) == wantCommitted {
		t.Fatal("hook outcome and required session effects disagree")
	}
	if wantCommitted {
		before, after := h.before.Load(), h.after.Load()
		for range 2 {
			outcome, address, err := out.recover()
			if err != nil || outcome != identity.CommitOutcomeCommitted || address != (identity.IdentifierProjection{}) {
				t.Fatal("observer failure lost code-free committed recovery", err)
			}
		}
		if before != h.before.Load() || after != h.after.Load() {
			t.Fatal("recovery repeated callbacks")
		}
	}
	return wantCommitted
}

func proveOTPVerificationHookOutcome(t *testing.T, ctx context.Context, f liveStores, service *reference.EmailOTPVerificationService, r otp.EmailVerifyRequest, read func([]*http.Cookie) bool, cookies []*http.Cookie) {
	t.Helper()
	challenge, err := service.EmailVerificationChallenge(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := challenge.Target.Bindings()
	proveConfirmationHookOutcome(t, ctx, f, r.UserID, target.IdentifierID, func() confirmationHookResult {
		out, err := service.EmailVerify(ctx, r)
		return confirmationHookResult{outcome: out.Outcome, address: out.Address, err: err, recover: func() (identity.CommitOutcome, identity.IdentifierProjection, error) {
			caller := r.Caller.Clone()
			caller.Request.Action = "identity.otp.email-verify.recover"
			history, err := service.RecoverEmailVerify(ctx, otp.EmailVerifyRecoveryRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: caller, Flow: r.Flow, Recovery: out.Recovery})
			return history.Outcome, history.Address, err
		}}
	}, read, cookies, r.SendCommandID)
}

func proveOTPChangeHookOutcome(t *testing.T, ctx context.Context, f liveStores, service *reference.EmailOTPChangeService, r otp.EmailChangeConfirmRequest, read func([]*http.Cookie) bool, cookies []*http.Cookie) bool {
	t.Helper()
	challenge, err := service.EmailChangeChallenge(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := challenge.Target.Bindings()
	return proveConfirmationHookOutcome(t, ctx, f, r.UserID, target.IdentifierID, func() confirmationHookResult {
		out, err := service.EmailChangeConfirm(ctx, r)
		return confirmationHookResult{outcome: out.Outcome, address: out.Address, err: err, recover: func() (identity.CommitOutcome, identity.IdentifierProjection, error) {
			caller := r.Caller.Clone()
			caller.Request.Action = "identity.otp.email-change-confirm.recover"
			history, err := service.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{TenantID: r.TenantID, UserID: r.UserID, Caller: caller, Flow: r.Flow, Recovery: out.Recovery})
			return history.Outcome, history.Address, err
		}}
	}, read, cookies, r.SendCommandID)
}

func proveManagedChangeHookOutcome(t *testing.T, ctx context.Context, f liveStores, service emailManagementConsumer, r email.ChangeConfirmRequest, read func([]*http.Cookie) bool, cookies []*http.Cookie) bool {
	t.Helper()
	// The real before callback receives the authenticated target; obtain its ID
	// from the actual issued scope, not a fabricated request or test identifier.
	var pending string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id FROM identity.identifiers WHERE tenant_id=$1 AND NOT verified`, otpTenant).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	user := identity.UserID(r.Caller.Request.Resource.ID)
	return proveConfirmationHookOutcome(t, ctx, f, user, identity.IdentifierID(pending), func() confirmationHookResult {
		out, err := service.ChangeConfirm(ctx, r)
		return confirmationHookResult{outcome: out.Outcome, address: out.Address, err: err, recover: func() (identity.CommitOutcome, identity.IdentifierProjection, error) {
			history, err := service.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: out.Recovery, Caller: r.Caller})
			return history.Outcome, identity.IdentifierProjection{}, err
		}}
	}, read, cookies, "")
}
