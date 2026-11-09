package identityhttp_test

import (
	"errors"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestProviderRateRequiresBothSharedIPAndOriginalTransactionBudgets(t *testing.T) {
	l, backend := authLimiter(t, func() time.Time { return time.Unix(1800000000, 0) })
	facts := safeFacts(t, "198.51.100.1")
	for range 30 {
		out, err := l.AdmitProviderIP(t.Context(), facts, "identity.account.link-start", "configured")
		if err != nil || !out.Allowed {
			t.Fatal("provider IP budget denied early", err)
		}
	}
	if out, err := l.AdmitProviderIP(t.Context(), facts, "identity.oauth.callback", "configured"); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 20*time.Second {
		t.Fatal("start/callback did not share the provider IP budget", err, out)
	}
	if out, err := l.AdmitProviderIP(t.Context(), facts, "identity.oauth.callback", "another"); err != nil || !out.Allowed {
		t.Fatal("different configured providers shared a bucket", err)
	}
	for i := range 6 {
		// Moving IP does not replace the transaction resolved by its native owner.
		out, err := l.AdmitProviderTransaction(t.Context(), safeFacts(t, "198.51.100.2"), "identity.oauth.callback", "configured", "original-transaction", 10*time.Minute)
		if i < 5 && (err != nil || !out.Allowed) {
			t.Fatal("original transaction budget denied early", i, err)
		}
		if i == 5 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 2*time.Minute) {
			t.Fatal("transaction budget bypass", err, out)
		}
	}
	for _, action := range []string{"identity.password.signin", "unknown"} {
		if _, err := l.AdmitProviderIP(t.Context(), facts, action, "configured"); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("unrelated operation borrowed provider admission", action, err)
		}
	}
	for _, lifetime := range []time.Duration{0, time.Second - 1, 10*time.Minute + 1} {
		if out, err := l.AdmitProviderTransaction(t.Context(), facts, "identity.oauth.callback", "configured", "original", lifetime); !errors.Is(err, identityhttp.ErrInvalidInput) || out.Allowed {
			t.Fatal("invalid original transaction lifetime accepted", err, out)
		}
	}
	backend.mode.Store(1)
	if out, err := l.AdmitProviderIP(t.Context(), facts, "identity.oauth.callback", "another"); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("provider IP admission failed open during an outage", err, out)
	}
	if out, err := l.AdmitProviderTransaction(t.Context(), facts, "identity.oauth.callback", "configured", "another", time.Minute); !errors.Is(err, identityhttp.ErrRateUnavailable) || out.Allowed {
		t.Fatal("provider transaction admission failed open during an outage", err, out)
	}
}
