//go:build integration

package reference_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func configureReferencePreAuth(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.OTP.PreAuth = &reference.OTPPreAuthConfiguration{ActorID: "preauth-service", Origin: "https://identity.example.invalid", LookupKeyVersion: 3, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: cookie}
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
}

func issueOTPGraphPreAuth(t *testing.T, ctx context.Context, f reference.FeatureSet) otp.SendFlow {
	t.Helper()
	owner, err := f.PreAuth()
	if err != nil {
		t.Fatal("selected initiation handle", err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	i := session.PreAuthPrepareInput{CommandID: id, TenantID: "not-selected", CorrelationID: string(id), Remember: remember}
	if _, err = owner.Prepare(ctx, i); err == nil {
		t.Fatal("foreign tenant prepared original flow")
	}
	i.TenantID = otpTenant
	p, err := owner.Prepare(ctx, i)
	if err != nil {
		t.Fatal("native flow preparation", err)
	}
	c, ok := p.Command()
	if !ok {
		t.Fatal("original command absent")
	}
	out, err := owner.Issue(ctx, p)
	if err != nil || out.CommitOutcome != identity.CommitOutcomeCommitted || out.Replayed {
		t.Fatal("native flow issuance", err)
	}
	spec, err := out.Flow.Bindings()
	if err != nil || spec.Binding.Intent.Remember != remember || spec.Binding.Intent.Origin != "https://identity.example.invalid" || spec.Binding.Intent.Action != "identity.otp.signin" {
		t.Fatal("original flow profile changed", err)
	}
	if out.Cookie.Name != "__Host-identity_flow" || out.Cookie.Value != "" || !out.Cookie.Secure || !out.Cookie.HttpOnly || out.Cookie.MaxAge < 1 || out.Cookie.MaxAge > 300 {
		t.Fatal("flow cookie profile weakened")
	}
	wire, err := out.Token.Reveal()
	if err != nil {
		t.Fatal("new commitment withheld flow bearer", err)
	}
	if _, err = out.Token.Reveal(); err == nil {
		t.Fatal("flow bearer revealed twice")
	}
	if repeated, err := owner.Issue(ctx, p); err == nil || repeated.Token != (session.Token{}) {
		t.Fatal("local preparation executed twice")
	}
	history, err := owner.Recover(ctx, c)
	if err != nil || history.CommitOutcome != identity.CommitOutcomeCommitted || !history.Replayed {
		t.Fatal("outcome-only initiation recovery", err)
	}
	if history.Token != (session.Token{}) || history.Cookie.Name != "" {
		t.Fatal("recovery revealed another flow cookie")
	}
	flow, err := otp.NewPreAuthSendFlow(spec.Binding.ID, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func TestReferencePreAuthMigrationEnablementOrders(t *testing.T) {
	for _, initiationFirst := range []bool{true, false} {
		name := "signin-first"
		if initiationFirst {
			name = "initiation-first"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f := newLiveStoresProfile(t, ctx, false)
			c, deps, _ := otpGraphConfiguration(t, f.config)
			deps.PostgreSQL = f.pool
			configureReferencePreAuth(t, &c)
			configureReferenceSignin(t, &c)
			initial := c
			selected := *c.OTP
			selected.PreAuth = nil
			if initiationFirst {
				selected.Signin = nil
			}
			initial.OTP = &selected
			first, err := reference.ComposeStores(initial, deps)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := first.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			installOTPGraphFixture(t, ctx, f, first)
			apply := func(stores reference.StoreSet, id string, modules []reference.ModuleID) {
				t.Helper()
				plan, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
				if err != nil {
					t.Fatal("selected native plan", err)
				}
				key, _ := identity.NewIdempotencyKey([]byte(id))
				r := reference.ReferenceMigrationApplyRequest{CommandID: identity.CommandID(id), Plan: plan.Plan, IdempotencyKey: key}
				if out, err := stores.ReferenceMigrationApply(ctx, r); err != nil || out.Result.State() != reference.MigrationApplied {
					t.Fatal("selected native apply", err)
				}
				if out, err := stores.ReferenceMigrationApply(ctx, r); err != nil || out.Result.State() != reference.MigrationApplied {
					t.Fatal("original native replay", err)
				}
			}
			if initiationFirst {
				initiatedConfig := initial
				initiatedOTP := selected
				initiatedOTP.PreAuth = c.OTP.PreAuth
				initiatedConfig.OTP = &initiatedOTP
				initiated, err := reference.ComposeStores(initiatedConfig, deps)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := initiated.Close(context.Background()); err != nil {
						t.Error(err)
					}
				})
				apply(initiated, "initial_initiation_command", []reference.ModuleID{"identity/session/postgres"})
			}
			both, err := reference.ComposeStores(c, deps)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := both.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			apply(both, "later_selected_profile_command", []reference.ModuleID{"identity/otp/postgres", "identity/session/postgres"})
			// A reconstructed owner must discover all independent histories, not
			// infer completeness from the maximum module version alone.
			restarted, err := reference.ComposeStores(c, deps)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := restarted.Close(context.Background()); err != nil {
					t.Error(err)
				}
			})
			modules := []reference.ModuleID{"identity/otp/postgres", "identity/session/postgres"}
			check, err := restarted.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: modules})
			if err != nil || len(check.Statuses) != 2 {
				t.Fatal("reconstructed profile discovery", err)
			}
			for _, status := range check.Statuses {
				if status.Compatibility != reference.MigrationCompatible {
					t.Fatal("selected owner incomplete", status)
				}
			}
			plan, err := restarted.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
			if err != nil || len(plan.Plan.Steps) != 0 {
				t.Fatal("reconstructed owner proposed duplicate work", err)
			}
		})
	}
}
