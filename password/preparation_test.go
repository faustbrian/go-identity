package password

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password"
)

func TestPublicHashPreparationRequiresCompletedOwnedScreening(t *testing.T) {
	w := testPasswordWork(t)
	p := screeningPolicy(t, creatingActions)
	now := time.Date(2026, 10, 9, 20, 0, 0, 0, time.UTC)
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	for _, action := range creatingActions {
		for _, scenario := range []string{"clean", "breached", "unavailable", "missing", "foreign"} {
			t.Run(string(action)+"/"+scenario, func(t *testing.T) {
				calls := 0
				prepared, err := NewHashPreparer(HashPreparationConfig{Primitive: w.primitive, MinimumBytes: w.minimum, MaximumBytes: w.maximum, Timeout: w.timeout, DummyHash: w.dummy, Policy: p, Now: func() time.Time { return now }, Collect: func(ctx context.Context, c risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
					calls++
					if _, bounded := ctx.Deadline(); !bounded || candidate.Len() != secret.Len() {
						t.Fatal("provider work lost bound or candidate custody")
					}
					observation := risk.PasswordObservation{ObservedAt: now, CheckedAt: now, ValidUntil: now.Add(time.Hour)}
					if scenario == "breached" {
						observation.BreachCount = 1
					}
					if scenario == "unavailable" {
						observation = risk.PasswordObservation{Failure: risk.ProviderUnavailable}
					}
					facts := screeningFacts(t, p, c, observation)
					if scenario == "missing" {
						facts = facts[:1]
					}
					if scenario == "foreign" {
						facts[1].Tenant = "foreign"
					}
					return facts, nil
				}})
				if err != nil || calls != 0 {
					t.Fatal("constructor performed provider IO or denied valid configuration", err)
				}
				hash, assessment, err := prepared.Prepare(context.Background(), secret, risk.Context{Tenant: "tenant", Operation: action, Attempt: "attempt"})
				if scenario == "clean" {
					if err != nil || hash.String() == "" || assessment.Decision.Action != risk.Allow {
						t.Fatal("complete preparation denied", err)
					}
					match, err := w.primitive.Verify(context.Background(), []byte("public-test-only"), hash.String())
					if err != nil || !match.Match() {
						t.Fatal("prepared verifier changed candidate bytes", err)
					}
				} else if hash.String() != "" || !errors.Is(err, ErrPasswordWork) {
					t.Fatal("incomplete screening disclosed a hash")
				}
				if calls != 1 {
					t.Fatal("provider work repeated")
				}
			})
		}
	}
}

func TestHashPreparationZeroAndUnselectedActionsDeny(t *testing.T) {
	for _, p := range []*HashPreparer{nil, {}} {
		if hash, _, err := p.Prepare(context.Background(), primitive.Secret{}, risk.Context{}); err == nil || hash.String() != "" {
			t.Fatal("zero preparer disclosed hash")
		}
	}
	w := testPasswordWork(t)
	policy := screeningPolicy(t, []risk.Action{"identity.password.change"})
	p, err := NewHashPreparer(HashPreparationConfig{Primitive: w.primitive, MinimumBytes: w.minimum, MaximumBytes: w.maximum, Timeout: w.timeout, DummyHash: w.dummy, Policy: policy, Now: time.Now, Collect: func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
		t.Fatal("unselected action accessed provider")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	for _, action := range []risk.Action{"identity.password.verify", "identity.password.signin", "identity.password.signup", "alias.change"} {
		if hash, _, err := p.Prepare(context.Background(), secret, risk.Context{Tenant: "tenant", Operation: action, Attempt: "attempt"}); err == nil || hash.String() != "" {
			t.Fatal("unselected creating action prepared hash")
		}
	}
}

func TestHashPreparationConfigurationAndCancellation(t *testing.T) {
	w := testPasswordWork(t)
	policy := screeningPolicy(t, []risk.Action{"identity.password.change"})
	now := time.Date(2026, 10, 9, 20, 0, 0, 0, time.UTC)
	calls := 0
	c := HashPreparationConfig{Primitive: w.primitive, MinimumBytes: w.minimum, MaximumBytes: w.maximum, Timeout: w.timeout, DummyHash: w.dummy, Policy: policy, Now: func() time.Time { return now }, Collect: func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error) {
		calls++
		panic("private synthetic provider diagnostic")
	}}
	for _, mutate := range []func(*HashPreparationConfig){
		func(c *HashPreparationConfig) { c.Primitive = nil },
		func(c *HashPreparationConfig) { c.MinimumBytes = 0 },
		func(c *HashPreparationConfig) { c.MaximumBytes = c.MinimumBytes - 1 },
		func(c *HashPreparationConfig) { c.MaximumBytes = 1 << 21 },
		func(c *HashPreparationConfig) { c.Timeout = 0 },
		func(c *HashPreparationConfig) { c.Timeout = 11 * time.Second },
		func(c *HashPreparationConfig) { c.DummyHash = primitive.EncodedHash{} },
		func(c *HashPreparationConfig) { c.Policy = risk.Policy{} },
		func(c *HashPreparationConfig) { c.Now = nil },
		func(c *HashPreparationConfig) { c.Collect = nil },
	} {
		bad := c
		mutate(&bad)
		if p, err := NewHashPreparer(bad); p != nil || !errors.Is(err, ErrPasswordWork) || calls != 0 {
			t.Fatal("invalid configuration constructed or performed IO")
		}
	}
	p, err := NewHashPreparer(c)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := primitive.NewSecret([]byte("public-test-only"))
	defer secret.Destroy()
	binding := risk.Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if hash, _, err := p.Prepare(ctx, secret, binding); hash.String() != "" || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("cancelled work reached provider or disclosed hash")
	}
	if hash, _, err := p.Prepare(nil, secret, binding); hash.String() != "" || !errors.Is(err, ErrPasswordWork) || calls != 0 {
		t.Fatal("nil context reached provider")
	}
	if hash, _, err := p.Prepare(context.Background(), secret, binding); hash.String() != "" || !errors.Is(err, ErrPasswordWork) || calls != 1 || strings.Contains(err.Error(), "private") {
		t.Fatal("provider panic escaped or disclosed material")
	}
	for _, value := range []any{c, p, struct{ hidden HashPreparer }{*p}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%x", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, value), w.dummy.String()) {
				t.Fatal("diagnostics exposed verifier material")
			}
		}
	}
	for _, value := range []any{c, p} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit serialization succeeded")
		}
	}
}
