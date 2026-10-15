package identity_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

func TestPasswordSignupInputRetainsOriginalCustodyWithoutVerifier(t *testing.T) {
	s := passwordSignupSpec(true)
	want := []byte(" original\x00\xffsignup candidate ")
	p, err := primitive.NewSecret(want)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Destroy()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32))
	c, err := identity.NewFeaturePasswordSignupInputCommand(s, p, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	s.Binding.ActorID, s.Fields[0].Name = "changed", "changed"
	meta, ok := c.PasswordSignupInputFeature()
	if !ok || meta.Binding != passwordSignupSpec(true).Binding {
		t.Fatal("original input scope lost")
	}
	meta.Fields[0].Name = "returned-mutation"
	meta, _ = c.PasswordSignupInputFeature()
	if meta.Fields[0].Name == "returned-mutation" {
		t.Fatal("input metadata aliased")
	}
	borrowed, cookie, ok := c.PasswordSignupInputCustody()
	if !ok || cookie.Token() != wire {
		t.Fatal("input cookie lost")
	}
	if err := borrowed.Use(func(raw []byte) error {
		if !bytes.Equal(raw, want) {
			t.Error("original candidate normalized")
		}
		clear(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.Use(func(raw []byte) error {
		if !bytes.Equal(raw, want) {
			t.Error("borrow mutated secret owner")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertSigninLegacyClosed(t, c)
	if _, ok := c.PasswordSigninFeature(); ok {
		t.Fatal("signup input became signin")
	}
	if _, _, ok := c.PasswordSigninCustody(); ok {
		t.Fatal("signup input became signin custody")
	}
	if _, ok := c.PasswordSignupFeature(); ok {
		t.Fatal("input became generated signup")
	}
	if _, _, ok := c.PasswordSignupCustody(); ok {
		t.Fatal("input fabricated verifier")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		text := fmt.Sprintf(verb, c)
		if strings.Contains(text, wire) || strings.Contains(text, "signup candidate") {
			t.Fatal("input diagnostic disclosed custody")
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("input command serialized")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			q, cookie, ok := c.PasswordSignupInputCustody()
			if !ok || q.Len() != len(want) || cookie.Token() != wire {
				t.Error("concurrent input borrow changed")
			}
		})
	}
	wg.Wait()
	borrowed.Destroy()
	q, _, ok := c.PasswordSignupInputCustody()
	if !ok || q.Len() != 0 || p.Len() != 0 {
		t.Fatal("input destruction is not shared")
	}
	if _, ok := c.PasswordSignupInputFeature(); !ok {
		t.Fatal("destruction removed safe scope")
	}
	if _, err := identity.NewFeaturePasswordSignupInputCommand(passwordSignupSpec(true), p, cookie); err == nil {
		t.Fatal("destroyed input admitted")
	}
}

func TestPasswordSignupInputRejectsWrongProfileAndMissingCustody(t *testing.T) {
	p, _ := primitive.NewSecret([]byte("synthetic candidate"))
	defer p.Destroy()
	b := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{24}, 32)))
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { *s = passwordSignupSpec(false) },
		func(s *identity.FeatureCommandSpec) { *s = passwordSigninSpec(true) },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/otp" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion = 2; s.Binding.SchemaVersion = 2 },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "" },
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
	} {
		s := passwordSignupSpec(true)
		mutate(&s)
		c, err := identity.NewFeaturePasswordSignupInputCommand(s, p, b)
		if _, ok := c.PasswordSignupInputFeature(); err == nil || ok {
			t.Fatal("wrong input profile admitted")
		}
	}
	if _, err := identity.NewFeaturePasswordSignupInputCommand(passwordSignupSpec(true), primitive.Secret{}, b); err == nil {
		t.Fatal("missing password admitted")
	}
	if _, err := identity.NewFeaturePasswordSignupInputCommand(passwordSignupSpec(true), p, auth.BearerCredential{}); err == nil {
		t.Fatal("missing cookie admitted")
	}
	if _, ok := (identity.Command{}).PasswordSignupInputFeature(); ok {
		t.Fatal("zero input metadata")
	}
	if _, _, ok := (identity.Command{}).PasswordSignupInputCustody(); ok {
		t.Fatal("zero input custody")
	}
}
