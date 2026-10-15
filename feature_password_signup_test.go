package identity_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func passwordSignupSpec(anonymous bool) identity.FeatureCommandSpec {
	s := passwordSigninSpec(anonymous)
	s.Operation.OperationID, s.Operation.SchemaID = "identity.password.signup", "password-signup"
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func TestPasswordSignupPreservesPairedCustodyAndFrozenScope(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		s := passwordSignupSpec(anonymous)
		hash := "$synthetic-only$original-registration-verifier"
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		c, err := identity.NewFeaturePasswordSignupCommand(s, hash, auth.NewBearerCredential(wire))
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.ActorID, s.Fields[0].Name = "changed", "changed"
		meta, ok := c.PasswordSignupFeature()
		if !ok || meta.Binding != passwordSignupSpec(anonymous).Binding {
			t.Fatal("registration scope lost")
		}
		meta.Fields[0].Name = "projection-mutation"
		meta, _ = c.PasswordSignupFeature()
		if meta.Fields[0].Name == "projection-mutation" {
			t.Fatal("metadata alias")
		}
		got, cookie, ok := c.PasswordSignupCustody()
		if !ok || got != hash || cookie.Token() != wire {
			t.Fatal("original paired custody lost")
		}
		assertSigninLegacyClosed(t, c)
		if _, ok := c.PasswordSigninFeature(); ok {
			t.Fatal("signup interpreted as signin")
		}
	}
}

func TestPasswordSignupBoundsProfileAndRedaction(t *testing.T) {
	s := passwordSignupSpec(true)
	cookie := func(n int) auth.BearerCredential {
		return auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, n)))
	}
	for _, n := range []int{1, 16384} {
		for _, size := range []int{32, 64} {
			if _, err := identity.NewFeaturePasswordSignupCommand(s, strings.Repeat("!", n), cookie(size)); err != nil {
				t.Fatal("exact boundary denied", err)
			}
		}
	}
	deny := func(spec identity.FeatureCommandSpec, hash string, b auth.BearerCredential) {
		t.Helper()
		c, err := identity.NewFeaturePasswordSignupCommand(spec, hash, b)
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) {
			t.Fatal("invalid transport not classified")
		}
		if h, b, ok := c.PasswordSignupCustody(); ok || h != "" || b.Token() != "" {
			t.Fatal("denial retained custody")
		}
	}
	for _, h := range []string{"", strings.Repeat("x", 16385), " x", "x\n", "x\x00", "x\x7f", "x\xff", "é"} {
		deny(s, h, cookie(32))
	}
	for _, b := range []auth.BearerCredential{{}, cookie(31), cookie(65), auth.NewBearerCredential(cookie(32).Token() + "="), auth.NewBearerCredential(" " + cookie(32).Token())} {
		deny(s, "synthetic", b)
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "other" },
		func(s *identity.FeatureCommandSpec) { s.Operation.OperationID = "identity.password.signin" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaID = "other-signup" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion = 2 },
		func(s *identity.FeatureCommandSpec) { s.Operation.RecordRequirement = identity.FeatureRecordRequired },
		func(s *identity.FeatureCommandSpec) { s.Operation.SubjectRequirement = 99 },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "" },
		func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "also-user" },
	} {
		q := s
		change(&q)
		deny(q, "synthetic", cookie(32))
	}
	// Unsupported native profiles must remain otherwise valid feature commands;
	// an inconsistent binding would only exercise the generic constructor guard.
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.password.signin"
			s.Binding.OperationID = s.Operation.OperationID
		},
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SchemaID = "other-signup"
			s.Binding.SchemaID = s.Operation.SchemaID
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion = 2; s.Binding.SchemaVersion = 2 },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.RecordRequirement = identity.FeatureRecordRequired
			s.Binding.RecordID = "valid-record"
		},
	} {
		q := s
		change(&q)
		if _, err := identity.NewFeatureCommand(q); err != nil {
			t.Fatal("unsupported profile fixture is not structurally valid", err)
		}
		deny(q, "synthetic", cookie(32))
	}
	hash, wire := "$synthetic-only$private-signup-verifier", cookie(32).Token()
	c, err := identity.NewFeaturePasswordSignupCommand(s, hash, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	type privateWrapper struct{ command identity.Command }
	for _, v := range []any{c, &c, privateWrapper{c}, &privateWrapper{c}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%d", "%s", "%q", "%x"} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(out, hash) || strings.Contains(out, wire) {
				t.Fatal("diagnostics disclosed custody")
			}
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("signup serialized")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			h, b, ok := c.PasswordSignupCustody()
			if !ok || h != hash || b.Token() != wire {
				t.Error("concurrent borrow changed")
			}
		})
	}
	wg.Wait()
	plain, _ := identity.NewFeaturePreAuthCommand(s, cookie(32))
	for _, other := range []identity.Command{{}, plain} {
		if h, b, ok := other.PasswordSignupCustody(); ok || h != "" || b.Token() != "" {
			t.Fatal("partial command gained custody")
		}
	}
}

func FuzzPasswordSignupTransport(f *testing.F) {
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	f.Add("synthetic", wire)
	f.Add("", wire)
	f.Add("a\n", "not-canonical")
	f.Fuzz(func(t *testing.T, hash, wire string) {
		if len(hash) > 16385 || len(wire) > 87 {
			return
		}
		c, err := identity.NewFeaturePasswordSignupCommand(passwordSignupSpec(true), hash, auth.NewBearerCredential(wire))
		h, b, ok := c.PasswordSignupCustody()
		if err != nil {
			if ok || h != "" || b.Token() != "" {
				t.Fatal("denial retained custody")
			}
			return
		}
		if !ok || h != hash || b.Token() != wire {
			t.Fatal("transport normalized")
		}
		assertSigninLegacyClosed(t, c)
	})
}
