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
	primitive "github.com/faustbrian/go-password/v2"
)

type passwordSigninBorrower interface {
	PasswordSigninFeature() (identity.FeatureCommandSpec, bool)
	PasswordSigninCustody() (primitive.Secret, auth.BearerCredential, bool)
}

func passwordSigninSpec(anonymous bool) identity.FeatureCommandSpec {
	s := featureCommandSpec()
	s.Operation = identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	s.Binding.OperationID, s.Binding.SchemaID, s.Binding.RecordID = s.Operation.OperationID, s.Operation.SchemaID, ""
	if anonymous {
		s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		s.Binding.UserID, s.Binding.AnonymousFlowID = "", "original-flow"
	}
	return s
}

func TestPasswordSigninPreservesRawSharedCustodyAndFrozenScope(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		s := passwordSigninSpec(anonymous)
		want := []byte(" unnormalized\x00\xffpassword ")
		p, err := primitive.NewSecret(want)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Destroy()
		wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
		c, err := identity.NewFeaturePasswordSigninCommand(s, p, auth.NewBearerCredential(wire))
		if err != nil {
			t.Fatal(err)
		}
		s.Binding.ActorID, s.Fields[0].Name = "changed", "changed"
		meta, ok := c.PasswordSigninFeature()
		if !ok || meta.Binding != passwordSigninSpec(anonymous).Binding {
			t.Fatal("original scope lost")
		}
		meta.Fields[0].Name = "returned-mutation"
		meta, _ = c.PasswordSigninFeature()
		if meta.Fields[0].Name == "returned-mutation" {
			t.Fatal("metadata alias")
		}
		borrowed, cookie, ok := c.PasswordSigninCustody()
		if !ok || cookie.Token() != wire {
			t.Fatal("original bearer lost")
		}
		if err := borrowed.Use(func(raw []byte) error {
			if !bytes.Equal(raw, want) {
				t.Error("password bytes changed")
			}
			clear(raw)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := p.Use(func(raw []byte) error {
			if !bytes.Equal(raw, want) {
				t.Error("borrow mutated owner")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertSigninLegacyClosed(t, c)
		type wrapper struct{ command identity.Command }
		for _, v := range []any{c, &c, wrapper{c}, &wrapper{c}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%d", "%x"} {
				text := fmt.Sprintf(verb, v)
				if strings.Contains(text, wire) || strings.Contains(text, "unnormalized") {
					t.Fatal("diagnostic disclosed custody")
				}
			}
		}
		if _, err := json.Marshal(c); err == nil {
			t.Fatal("secret command serialized")
		}
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				q, b, ok := c.PasswordSigninCustody()
				if !ok || q.Len() != len(want) || b.Token() != wire {
					t.Error("concurrent borrow changed")
				}
			})
		}
		wg.Wait()
		// Destroy through a borrowed copy must invalidate the original and all
		// command copies, without discarding the safe outcome correlation.
		borrowed.Destroy()
		q, _, ok := c.PasswordSigninCustody()
		if !ok || q.Len() != 0 || p.Len() != 0 || !errors.Is(q.Use(func([]byte) error { return nil }), primitive.ErrInvalidSecret) {
			t.Fatal("destruction did not share ownership")
		}
		if _, ok := c.PasswordSigninFeature(); !ok {
			t.Fatal("destruction lost recovery correlation")
		}
	}
}

func assertSigninLegacyClosed(t testing.TB, c identity.Command) {
	t.Helper()
	_, feature := c.Feature()
	_, hash := c.PasswordHash()
	_, hm := c.PasswordHashFeature()
	_, change := c.PasswordChangeFeature()
	_, _, _, custody := c.PasswordChangeCustody()
	_, code := c.OneTimeCode()
	_, cookie := c.PreAuthCookie()
	_, token := c.SessionToken()
	if feature || hash || hm || change || custody || code || cookie || token {
		t.Fatal("legacy path can omit signin custody")
	}
}

func TestPasswordSigninRejectsInvalidProfileAndDestroyedPassword(t *testing.T) {
	p, _ := primitive.NewSecret([]byte("candidate"))
	defer p.Destroy()
	b := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 64)))
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/otp" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.password.signup"
			s.Binding.OperationID = s.Operation.OperationID
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaID = "other"; s.Binding.SchemaID = "other" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion = 2; s.Binding.SchemaVersion = 2 },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.RecordRequirement = identity.FeatureRecordRequired
			s.Binding.RecordID = "target"
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.SubjectRequirement = 2 },
		func(s *identity.FeatureCommandSpec) { s.Binding.AnonymousFlowID = "mixed" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "" },
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
	} {
		s := passwordSigninSpec(false)
		mutate(&s)
		c, err := identity.NewFeaturePasswordSigninCommand(s, p, b)
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) {
			t.Fatal("invalid profile admitted")
		}
		if _, ok := c.PasswordSigninFeature(); ok {
			t.Fatal("invalid retained metadata")
		}
		if q, b, ok := c.PasswordSigninCustody(); ok || q.Len() != 0 || b.Token() != "" {
			t.Fatal("invalid retained custody")
		}
	}
	for _, wire := range []string{"", "short", b.Token() + "=", " " + b.Token(), base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 65))} {
		if _, err := identity.NewFeaturePasswordSigninCommand(passwordSigninSpec(false), p, auth.NewBearerCredential(wire)); err == nil {
			t.Fatal("malformed cookie admitted")
		}
	}
	if _, err := identity.NewFeaturePasswordSigninCommand(passwordSigninSpec(false), primitive.Secret{}, b); err == nil {
		t.Fatal("zero password admitted")
	}
	p.Destroy()
	if _, err := identity.NewFeaturePasswordSigninCommand(passwordSigninSpec(false), p, b); err == nil {
		t.Fatal("destroyed password admitted")
	}
	plain, _ := identity.NewFeatureCommand(passwordSigninSpec(false))
	for _, c := range []identity.Command{{}, plain} {
		if _, ok := c.PasswordSigninFeature(); ok {
			t.Fatal("other metadata variant admitted")
		}
		if _, _, ok := c.PasswordSigninCustody(); ok {
			t.Fatal("other custody variant admitted")
		}
	}
}

func FuzzPasswordSigninCookieAndSharedBytes(f *testing.F) {
	f.Add([]byte(" original password "), strings.Repeat("x", 32), false)
	f.Add([]byte{0, 255, 1}, strings.Repeat("x", 64), true)
	f.Add([]byte{}, "", false)
	f.Fuzz(func(t *testing.T, raw []byte, cookieRaw string, anonymous bool) {
		if len(raw) > 4096 || len(cookieRaw) > 65 {
			return
		}
		p, err := primitive.NewSecret(raw)
		if err != nil {
			return
		}
		defer p.Destroy()
		wire := base64.RawURLEncoding.EncodeToString([]byte(cookieRaw))
		c, err := identity.NewFeaturePasswordSigninCommand(passwordSigninSpec(anonymous), p, auth.NewBearerCredential(wire))
		q, b, ok := c.PasswordSigninCustody()
		if len(cookieRaw) < 32 || len(cookieRaw) > 64 {
			if err == nil || ok || q.Len() != 0 || b.Token() != "" {
				t.Fatal("invalid cookie retained custody")
			}
			return
		}
		if err != nil || !ok || b.Token() != wire {
			t.Fatal("valid cookie altered")
		}
		if err := q.Use(func(got []byte) error {
			if !bytes.Equal(got, raw) {
				t.Error("password altered")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertSigninLegacyClosed(t, c)
	})
}

func TestPasswordSigninCommandHasExplicitNativeCustodyBoundary(t *testing.T) {
	// Runtime assertion: legacy command input cannot safely carry the password.
	// The actual constructor and lifecycle assertions follow once this native
	// boundary exists; ordinary Feature must never discard the new custody.
	if _, ok := any(identity.Command{}).(passwordSigninBorrower); !ok {
		t.Fatal("password signin command custody unavailable")
	}
}
