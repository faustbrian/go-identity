package risk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func captchaFlowInput() FlowContextInput {
	return FlowContextInput{Kind: FlowPreAuth, Tenant: "tenant", Operation: "identity.password.signin", AnonymousFlow: "anonymous", PreAuthTransaction: "transaction", ChallengeID: "challenge", RequestFingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
}

func TestCaptchaFlowBindingsConserveOriginalScopeWithoutAuthority(t *testing.T) {
	if _, err := (FlowContext{}).Bindings(); !errors.Is(err, ErrInvalidCaptchaReplay) {
		t.Fatal("zero flow exported a scope")
	}
	preauth := captchaFlowInput()
	authenticated := preauth
	authenticated.Kind, authenticated.Subject, authenticated.AnonymousFlow = FlowAuthenticated, "subject", ""
	authenticated.PreAuthTransaction, authenticated.Session = "", "session"
	administrator := authenticated
	administrator.Kind, administrator.Actor = FlowAdministrator, "administrator"
	for _, input := range []FlowContextInput{preauth, authenticated, administrator} {
		flow, err := NewFlowContext(input)
		if err != nil {
			t.Fatal(err)
		}
		got, err := flow.Bindings()
		if err != nil || got != input {
			t.Fatal("original closed flow scope changed", err)
		}
		got.Tenant, got.ChallengeID, got.RequestFingerprint = "other", "other", ""
		again, err := flow.Bindings()
		if err != nil || again != input {
			t.Fatal("returned scope mutation changed original flow", err)
		}
	}
}

func TestCaptchaReplayFramingRawBytesAndRotation(t *testing.T) {
	c := captchaReplayConfig(t)
	p, _ := NewCaptchaReplayPolicy(c)
	f, _ := NewFlowContext(captchaFlowInput())
	original, _ := p.Prepare(f, []byte("provider-token"))
	want := original.Bindings().Keys[0].Fingerprint
	for _, token := range []string{"Provider-token", " provider-token", "provider-token ", "provider-token\x00"} {
		next, err := p.Prepare(f, []byte(token))
		if err != nil || next.Bindings().Keys[0].Fingerprint == want {
			t.Fatal("token normalization or framing collision", err)
		}
	}
	for _, change := range []func(*CaptchaReplayPolicyConfig){
		func(v *CaptchaReplayPolicyConfig) { v.Provider = "recaptcha" },
		func(v *CaptchaReplayPolicyConfig) { v.Site = "other-site" },
		func(v *CaptchaReplayPolicyConfig) { v.APIProfile = "other-profile" },
		func(v *CaptchaReplayPolicyConfig) { v.ConfigurationVersion = "config-2" },
	} {
		d := c
		change(&d)
		np, err := NewCaptchaReplayPolicy(d)
		if err != nil {
			t.Fatal(err)
		}
		next, err := np.Prepare(f, []byte("provider-token"))
		if err != nil || next.Bindings().Keys[0].Fingerprint == want {
			t.Fatal("configured scope substitution", err)
		}
		if np.Validate(original, f) == nil {
			t.Fatal("foreign policy accepted preparation")
		}
	}
	c1, c2 := c, c
	c1.Site, c1.APIProfile = "ab", "c"
	c2.Site, c2.APIProfile = "a", "bc"
	a, _ := NewCaptchaReplayPolicy(c1)
	b, _ := NewCaptchaReplayPolicy(c2)
	ai, _ := a.Prepare(f, []byte("provider-token"))
	bi, _ := b.Prepare(f, []byte("provider-token"))
	if ai.Bindings().Keys[0] == bi.Bindings().Keys[0] {
		t.Fatal("adjacent length framing lost")
	}
	unicodeConfig := c
	unicodeConfig.Site = "é"
	unicodePolicy, _ := NewCaptchaReplayPolicy(unicodeConfig)
	unicodeIdentity, err := unicodePolicy.Prepare(f, []byte("provider-token"))
	// Independent OpenSSL oracle uses UTF-8 byte lengths, not rune counts.
	if err != nil || unicodeIdentity.Bindings().Keys[0].Fingerprint != "Db5jlDsOQb3M_u9qgJX3GiQQtHtdvAE8j4eKwxti0yM" {
		t.Fatal("UTF-8 framing oracle mismatch", err)
	}
	key, _ := NewCaptchaReplayKey(2, bytes.Repeat([]byte{2}, 32))
	c.Keys = append([]CaptchaReplayKey{key}, c.Keys...)
	rotated, err := NewCaptchaReplayPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	next, err := rotated.Prepare(f, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	keys := next.Bindings().Keys
	if len(keys) != 2 || keys[0].Version != 2 || keys[0].Fingerprint == want || keys[1].Version != 1 || keys[1].Fingerprint != want {
		t.Fatal("retained replay lookup identity lost")
	}
}

func TestCaptchaReplayBoundsFlowAndCustody(t *testing.T) {
	c := captchaReplayConfig(t)
	for _, change := range []func(*CaptchaReplayPolicyConfig){
		func(v *CaptchaReplayPolicyConfig) { v.Policy = Policy{} },
		func(v *CaptchaReplayPolicyConfig) { v.Provider = "unknown" },
		func(v *CaptchaReplayPolicyConfig) { v.Site = "" },
		func(v *CaptchaReplayPolicyConfig) { v.Site = strings.Repeat("a", 513) },
		func(v *CaptchaReplayPolicyConfig) { v.Site = string([]byte{255}) },
		func(v *CaptchaReplayPolicyConfig) { v.APIProfile = "" },
		func(v *CaptchaReplayPolicyConfig) { v.ConfigurationVersion = strings.Repeat("a", 65) },
		func(v *CaptchaReplayPolicyConfig) { v.MaxTokenBytes = 0 },
		func(v *CaptchaReplayPolicyConfig) { v.MaxTokenBytes = 8193 },
		func(v *CaptchaReplayPolicyConfig) { v.Keys = nil },
		func(v *CaptchaReplayPolicyConfig) { v.Keys = []CaptchaReplayKey{{}} },
		func(v *CaptchaReplayPolicyConfig) { v.Keys = append(v.Keys, v.Keys[0]) },
	} {
		bad := c
		change(&bad)
		if _, err := NewCaptchaReplayPolicy(bad); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid configuration admitted", err)
		}
	}
	for _, n := range []int{0, 31, 129} {
		if _, err := NewCaptchaReplayKey(1, make([]byte, n)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid key size")
		}
	}
	if _, err := NewCaptchaReplayKey(0, make([]byte, 32)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("zero key version")
	}
	for _, n := range []int{32, 33, 128} {
		if _, err := NewCaptchaReplayKey(1, make([]byte, n)); err != nil {
			t.Fatal("supported key bound", err)
		}
	}
	in := captchaFlowInput()
	for _, change := range []func(*FlowContextInput){
		func(v *FlowContextInput) { v.Kind = "unknown" },
		func(v *FlowContextInput) { v.Tenant = "" },
		func(v *FlowContextInput) { v.Operation = "signin" },
		func(v *FlowContextInput) { v.Operation = Action(strings.Repeat("x", 129)) },
		func(v *FlowContextInput) { v.Subject = "subject" },
		func(v *FlowContextInput) { v.AnonymousFlow = "" },
		func(v *FlowContextInput) { v.PreAuthTransaction = "" },
		func(v *FlowContextInput) { v.Session = "session" },
		func(v *FlowContextInput) { v.Actor = "actor" },
		func(v *FlowContextInput) { v.ChallengeID = "" },
		func(v *FlowContextInput) { v.RequestFingerprint = strings.Repeat("!", 43) },
	} {
		bad := in
		change(&bad)
		if _, err := NewFlowContext(bad); !errors.Is(err, ErrInvalidCaptchaReplay) {
			t.Fatal("mixed/invalid flow admitted", err)
		}
	}
	for _, kind := range []FlowKind{FlowAuthenticated, FlowAdministrator} {
		next := in
		next.Kind = kind
		next.Subject = "subject"
		next.AnonymousFlow = ""
		next.PreAuthTransaction = ""
		if kind == FlowAuthenticated {
			next.Session = "session"
		} else {
			next.Actor = "actor"
		}
		if _, err := NewFlowContext(next); err != nil {
			t.Fatal("valid closed flow", err)
		}
	}
	p, _ := NewCaptchaReplayPolicy(c)
	f, _ := NewFlowContext(in)
	for _, token := range [][]byte{nil, {255}, bytes.Repeat([]byte{'x'}, 8193)} {
		if got, err := p.Prepare(f, token); !errors.Is(err, ErrInvalidCaptchaReplay) || len(got.Bindings().Keys) != 0 {
			t.Fatal("invalid token admitted")
		}
	}
	for _, n := range []int{8191, 8192} {
		if _, err := p.Prepare(f, bytes.Repeat([]byte{'x'}, n)); err != nil {
			t.Fatal("supported token boundary", err)
		}
	}
	small := c
	small.MaxTokenBytes = 8
	smallPolicy, _ := NewCaptchaReplayPolicy(small)
	for _, n := range []int{7, 8, 9} {
		_, err := smallPolicy.Prepare(f, bytes.Repeat([]byte{'x'}, n))
		if (n <= 8) != (err == nil) {
			t.Fatal("configured token bound", n, err)
		}
	}
	if _, err := (CaptchaReplayPolicy{}).Prepare(f, []byte("token")); err == nil {
		t.Fatal("zero policy")
	}
	if _, err := p.Prepare(FlowContext{}, []byte("token")); err == nil {
		t.Fatal("zero flow")
	}
	if p.Validate(CaptchaReplayIdentity{}, f) == nil {
		t.Fatal("zero identity")
	}
	closed := in
	closed.Operation = "identity.risk.captcha-verify"
	cf, _ := NewFlowContext(closed)
	if _, err := p.Prepare(cf, []byte("token")); err == nil {
		t.Fatal("closed deny action prepared token")
	}
	secret := bytes.Repeat([]byte{7}, 32)
	key, _ := NewCaptchaReplayKey(3, secret)
	c.Keys = []CaptchaReplayKey{key}
	owned, _ := NewCaptchaReplayPolicy(c)
	before, _ := owned.Prepare(f, []byte("token"))
	secret[0] = 9
	c.Keys[0] = CaptchaReplayKey{}
	projection := before.Bindings()
	projection.Keys[0].Fingerprint = "changed"
	projection.Flow.Tenant = "changed"
	after, _ := owned.Prepare(f, []byte("token"))
	if before.Bindings().Keys[0] != after.Bindings().Keys[0] || owned.Validate(before, f) != nil {
		t.Fatal("caller mutation changed private custody")
	}
}

func TestCaptchaReplayRedactionAndConcurrentDerivation(t *testing.T) {
	c := captchaReplayConfig(t)
	p, _ := NewCaptchaReplayPolicy(c)
	in := captchaFlowInput()
	f, _ := NewFlowContext(in)
	i, _ := p.Prepare(f, []byte("provider-token"))
	b := i.Bindings()
	for _, value := range []any{in, f, c.Keys[0], c, p, b.Keys[0], b, i} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, "provider-token") || strings.Contains(out, b.Keys[0].Fingerprint) || strings.Contains(out, in.RequestFingerprint) {
				t.Fatal("diagnostic custody leak")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("serialization admitted", err)
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, ErrSensitiveSerialization) {
			t.Fatal("text serialization admitted")
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := p.Prepare(f, []byte("provider-token"))
			if err != nil || got.Bindings().Keys[0] != b.Keys[0] {
				t.Error("concurrent derivation changed")
			}
		}()
	}
	wg.Wait()
}

func FuzzCaptchaReplayBoundedRawToken(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("token"), []byte(" token"), []byte("é"), {255}, bytes.Repeat([]byte{'a'}, 8192), bytes.Repeat([]byte{'a'}, 8193)} {
		f.Add(seed)
	}
	c := captchaReplayConfig(f)
	// Construct outside fuzz callbacks; use one immutable configuration.
	p, err := NewCaptchaReplayPolicy(c)
	if err != nil {
		f.Fatal(err)
	}
	flow, err := NewFlowContext(captchaFlowInput())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, token []byte) {
		if len(token) > 8193 {
			return
		}
		a, err := p.Prepare(flow, token)
		if err != nil {
			if len(a.Bindings().Keys) != 0 {
				t.Fatal("failed preparation exposed identity")
			}
			return
		}
		b, err := p.Prepare(flow, token)
		if err != nil || len(token) == 0 || len(token) > 8192 || a.Bindings().Keys[0] != b.Bindings().Keys[0] || p.Validate(a, flow) != nil {
			t.Fatal("invalid/non-deterministic preparation")
		}
	})
}

func captchaReplayConfig(t testing.TB) CaptchaReplayPolicyConfig {
	t.Helper()
	key, err := NewCaptchaReplayKey(1, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy(testPolicyConfig())
	if err != nil {
		t.Fatal(err)
	}
	return CaptchaReplayPolicyConfig{Policy: policy, Provider: "turnstile", Site: "site", APIProfile: "siteverify/v0", ConfigurationVersion: "config-1", MaxTokenBytes: 8192, Keys: []CaptchaReplayKey{key}}
}

func TestCaptchaReplayPinnedEncodingAndCommandIndependence(t *testing.T) {
	c := captchaReplayConfig(t)
	p, err := NewCaptchaReplayPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	in := captchaFlowInput()
	f, err := NewFlowContext(in)
	if err != nil {
		t.Fatal(err)
	}
	original, err := p.Prepare(f, []byte("provider-token"))
	if err != nil {
		t.Fatal(err)
	}
	b := original.Bindings()
	// Pinned independent OpenSSL HMAC oracle, not a production helper.
	const expected = "ke_1U2jEhye1sVLGszYbnAeU4ulXa4HU_DHjuqWhmT8"
	if len(b.Keys) != 1 || b.Keys[0].Version != 1 || b.Keys[0].Fingerprint != expected {
		t.Fatal("wrong pinned replay identity")
	}
	for _, change := range []func(*FlowContextInput){
		func(v *FlowContextInput) { v.ChallengeID = "other-challenge" },
		func(v *FlowContextInput) { v.RequestFingerprint = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" },
		func(v *FlowContextInput) { v.Operation = "identity.password.change" },
		func(v *FlowContextInput) { v.Tenant = "other-tenant" },
	} {
		changed := in
		change(&changed)
		flow, err := NewFlowContext(changed)
		if err != nil {
			t.Fatal(err)
		}
		next, err := p.Prepare(flow, []byte("provider-token"))
		if err != nil {
			t.Fatal(err)
		}
		if next.Bindings().Keys[0].Fingerprint != expected {
			t.Fatal("flow entered prescribed replay MAC")
		}
		if p.Validate(original, flow) == nil {
			t.Fatal("original replay provenance crossed issuance flow")
		}
	}
}
