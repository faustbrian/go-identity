package session_test

import (
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func TestStoredRememberPolicyPreservesEveryResolvedLimit(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		c := config()
		c.IdleTTL = 23*time.Hour + time.Nanosecond
		c.RefreshAfter = 3*time.Hour + time.Nanosecond
		c.FreshFor = 21*time.Minute + time.Nanosecond
		original, err := session.ResolveRememberPolicy(choice, c)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := original.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		if spec.Choice != choice || spec.AbsoluteTTL != original.AbsoluteTTL() || spec.IdleTTL != c.IdleTTL || spec.RefreshAfter != c.RefreshAfter || spec.FreshFor != c.FreshFor {
			t.Fatalf("limits lost: %+v", spec)
		}
		restored, err := session.NewRememberPolicy(spec)
		if err != nil || restored != original {
			t.Fatalf("restore changed policy: %v", err)
		}
		issued := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
		for _, offset := range []time.Duration{0, c.RefreshAfter, c.FreshFor, c.IdleTTL, original.AbsoluteTTL()} {
			want, we := original.Evaluate(issued.Add(offset), issued, issued, issued)
			got, ge := restored.Evaluate(issued.Add(offset), issued, issued, issued)
			if got != want || !errors.Is(ge, we) {
				t.Fatalf("restored lifetime differs at %v: %+v %v / %+v %v", offset, got, ge, want, we)
			}
		}
		spec.IdleTTL = 5 * time.Minute
		again, _ := original.Bindings()
		if again.IdleTTL != c.IdleTTL {
			t.Fatal("projection mutation changed original")
		}
	}
}

func TestStoredRememberPolicyRejectsUnresolvedAndNoncanonicalValues(t *testing.T) {
	if _, err := (session.RememberPolicy{}).Bindings(); !errors.Is(err, session.ErrInvalidPolicy) {
		t.Fatal("zero policy exported")
	}
	original, _ := session.ResolveRememberPolicy(session.PersistentSession, config())
	good, _ := original.Bindings()
	for _, change := range []func(*session.RememberPolicySpec){
		func(s *session.RememberPolicySpec) { s.Choice = session.RememberDefault },
		func(s *session.RememberPolicySpec) { s.Choice = 99 },
		func(s *session.RememberPolicySpec) { s.AbsoluteTTL = 0 },
		func(s *session.RememberPolicySpec) { s.AbsoluteTTL = 31 * 24 * time.Hour },
		func(s *session.RememberPolicySpec) { s.IdleTTL = 4 * time.Minute },
		func(s *session.RememberPolicySpec) { s.IdleTTL = s.AbsoluteTTL + 1 },
		func(s *session.RememberPolicySpec) { s.RefreshAfter = 0 },
		func(s *session.RememberPolicySpec) { s.RefreshAfter = s.IdleTTL + 1 },
		func(s *session.RememberPolicySpec) { s.FreshFor = 14 * time.Minute },
		func(s *session.RememberPolicySpec) { s.FreshFor = 25 * time.Hour },
		func(s *session.RememberPolicySpec) { s.Choice = session.BrowserSession },
		func(s *session.RememberPolicySpec) {
			s.AbsoluteTTL = time.Hour
			s.IdleTTL = time.Hour
			s.RefreshAfter = time.Minute
			s.FreshFor = 2 * time.Hour
		},
	} {
		bad := good
		change(&bad)
		if _, err := session.NewRememberPolicy(bad); !errors.Is(err, session.ErrInvalidPolicy) {
			t.Fatalf("invalid stored policy accepted: %+v", bad)
		}
	}
}
