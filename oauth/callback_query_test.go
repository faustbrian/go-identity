package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func queryProfile() oauth.ProviderProfile {
	return oauth.ProviderProfile{
		ID: "generic", Version: 1, Issuer: "https://issuer.example", ClientID: "client",
		AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: "https://issuer.example/token", RedirectURI: "https://app.example/callback",
		ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"},
		ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32,
		Timeout: time.Second, ClockSkew: time.Minute, MaxResponseBytes: 65536, MaxTokenBytes: 16384, MaxCodeBytes: 4096,
	}
}

func queryResponse(member string) string {
	return member + "&state=" + testNonce + "&iss=https%3A%2F%2Fissuer.example"
}

func TestQueryCallbackProfileSnapshotsParseProvenance(t *testing.T) {
	for _, member := range []string{"code=synthetic", "error=access_denied"} {
		source := queryProfile()
		source.Version = 7
		source.Scopes = append(source.Scopes, "profile")
		source.Algorithms = append(source.Algorithms, "RS256")
		want := source
		want.Scopes = slices.Clone(source.Scopes)
		want.Algorithms = slices.Clone(source.Algorithms)
		parsed, err := oauth.ParseQueryCallback(context.Background(), queryResponse(member), source)
		if err != nil {
			t.Fatal(err)
		}
		defer parsed.Destroy()
		var alias oauth.Callback = parsed
		if !reflect.DeepEqual(parsed.Profile(), want) {
			t.Fatal("parse-time profile not retained")
		}
		source.Scopes[0], source.Algorithms[0] = "changed", "none"
		source.Version = 99
		source.ID, source.Issuer, source.ClientID, source.RedirectURI = "changed", "https://changed.example", "changed", "https://changed.example/callback"
		projection := alias.Profile()
		projection.Scopes[0], projection.Algorithms[0] = "changed-again", "none"
		projection.Version = 100
		projection.Issuer, projection.ClientID, projection.RedirectURI = "https://changed-again.example", "changed-again", "https://changed-again.example/callback"
		if !reflect.DeepEqual(parsed.Profile(), want) || !reflect.DeepEqual(alias.Profile(), want) {
			t.Fatal("source or returned profile mutated parse provenance")
		}
		alias.Destroy()
		if !reflect.DeepEqual(parsed.Profile(), want) || !reflect.DeepEqual(alias.Profile(), want) {
			t.Fatal("destruction erased safe profile metadata")
		}
		if input, ok := parsed.Input(); ok {
			if err := input.Use(context.Background(), func(context.Context, []byte, []byte) error {
				t.Fatal("alias destruction did not clear input")
				return nil
			}); err == nil {
				t.Fatal("destroyed input admitted")
			}
		} else if err := parsed.UseDeniedState(context.Background(), func(context.Context, []byte) error {
			t.Fatal("alias destruction did not clear denial state")
			return nil
		}); err == nil {
			t.Fatal("destroyed denial state admitted")
		}
	}
	var zero oauth.Callback
	if !reflect.DeepEqual(zero.Profile(), oauth.ProviderProfile{}) {
		t.Fatal("zero callback has profile provenance")
	}
	invalid, err := oauth.ParseQueryCallback(context.Background(), "invalid", queryProfile())
	defer invalid.Destroy()
	if err == nil || !reflect.DeepEqual(invalid.Profile(), oauth.ProviderProfile{}) {
		t.Fatal("invalid callback has profile provenance")
	}
}

func requireQueryError(t *testing.T, raw string, profile oauth.ProviderProfile) {
	t.Helper()
	result, err := oauth.ParseQueryCallback(context.Background(), raw, profile)
	defer result.Destroy()
	var classified *oauth.Error
	if !errors.As(err, &classified) || classified.Kind() != oauth.InvalidInput {
		t.Fatal("malformed callback did not return typed invalid input")
	}
	if _, ok := result.Input(); ok || result.Denied() {
		t.Fatal("malformed callback produced usable variant")
	}
}

func TestQueryCallbackRejectsAmbiguousOrMalformedResponse(t *testing.T) {
	good := queryResponse("code=exact")
	for _, raw := range []string{
		"", "?" + good, good + "#fragment", "code=exact&state=" + testNonce,
		strings.Replace(good, "issuer.example", "other.example", 1),
		strings.Replace(good, "issuer.example", "ISSUER.example", 1),
		strings.Replace(good, "issuer.example", "issuer.example%2F", 1),
		strings.Replace(good, "state="+testNonce, "state=not-canonical-state", 1),
		strings.Replace(good, "code=exact", "code=", 1),
		queryResponse("error="), queryResponse("error=access_denied&code=exact"),
		good + "&error_description=conflict", good + "&error_uri=%2Ferror",
		queryResponse("error=access_denied&error_description="),
		queryResponse("error=access_denied&error_uri=bad%20uri"),
		queryResponse("error=access_denied&error_uri=%25broken"),
		queryResponse("error=access_denied&error_uri=https%3A%2F%2Fexample.test%2F%7Bbad%7D"),
		queryResponse("error=access_denied&error_uri=%2Fbad%7Cpath"),
		queryResponse("error=access_denied&error_uri=%2Fbad%5Bpath%5D"),
		queryResponse("error=bad%22error"), queryResponse("error=access_denied&error_description=bad%5Cdescription"),
		queryResponse("code=%00"), queryResponse("code=%7F"), queryResponse("code=%C3%A4"),
		good + "&extension=%FF", good + "&extension=%", good + "&&extension=x", good + "&=x",
		good + "&bad%00name=x", good + "&bad%22name=x", good + "&extension=x&ext%65nsion=y",
	} {
		requireQueryError(t, raw, queryProfile())
	}
	for _, name := range []string{"code", "state", "iss", "error", "error_description", "error_uri"} {
		base := good
		if strings.HasPrefix(name, "error") {
			base = queryResponse("error=access_denied&error_description=description&error_uri=%2Ferror")
		}
		alias := "%" + fmt.Sprintf("%02x", name[0]) + name[1:]
		requireQueryError(t, base+"&"+alias+"=duplicate", queryProfile())
	}
	for _, name := range []string{"access_token", "id_token", "token_type", "expires_in", "response"} {
		requireQueryError(t, good+"&"+name+"=other-variant", queryProfile())
	}
}

func TestQueryCallbackBoundsAndExtensions(t *testing.T) {
	p := queryProfile()
	p.MaxCodeBytes = 1
	r, err := oauth.ParseQueryCallback(context.Background(), queryResponse("code=%20")+"&extension=%E2%98%83", p)
	if err != nil {
		t.Fatal("bounded valid extension or permitted code space rejected")
	}
	r.Destroy()
	requireQueryError(t, queryResponse("code=xx"), p)
	requireQueryError(t, queryResponse("code=%78%78"), p)
	requireQueryError(t, queryResponse("code=x")+"&extension="+strings.Repeat("x", 4097), p)
	requireQueryError(t, queryResponse("code=x")+"&"+strings.Repeat("n", 65)+"=x", p)
	requireQueryError(t, queryResponse("code=x")+"&error="+strings.Repeat("e", 257), p)
	for _, pair := range []struct {
		name  string
		limit int
	}{{"error", 256}, {"error_description", 1024}, {"error_uri", 2048}} {
		member := "error=access_denied&" + pair.name + "=" + strings.Repeat("x", pair.limit+1)
		if pair.name == "error" {
			member = "error=" + strings.Repeat("x", pair.limit+1)
		}
		requireQueryError(t, queryResponse(member), p)
	}
	members := queryResponse("code=x")
	for i := 0; i < 29; i++ {
		members += fmt.Sprintf("&x%d=v", i)
	}
	r, err = oauth.ParseQueryCallback(context.Background(), members, p)
	if err != nil {
		t.Fatal("maximum bounded member count rejected")
	}
	r.Destroy()
	requireQueryError(t, members+"&last=v", p)
	requireQueryError(t, queryResponse("code=x")+"&extension="+strings.Repeat("x", 3*p.MaxCodeBytes+16*1024), p)
}

func TestQueryCallbackRejectsMalformedProfileAndCancellation(t *testing.T) {
	for _, change := range []func(*oauth.ProviderProfile){
		func(p *oauth.ProviderProfile) { *p = oauth.ProviderProfile{} },
		func(p *oauth.ProviderProfile) { p.ID = "invalid id" }, func(p *oauth.ProviderProfile) { p.Version = 0 },
		func(p *oauth.ProviderProfile) { p.Issuer = "http://issuer.example" }, func(p *oauth.ProviderProfile) { p.ClientID = "" },
		func(p *oauth.ProviderProfile) { p.AuthorizationEndpoint = "" }, func(p *oauth.ProviderProfile) { p.TokenEndpoint = "" },
		func(p *oauth.ProviderProfile) { p.RedirectURI = "https://app.example/callback?override=yes" },
		func(p *oauth.ProviderProfile) { p.ClientAuthentication = "unknown" }, func(p *oauth.ProviderProfile) { p.Scopes = []string{"profile"} },
		func(p *oauth.ProviderProfile) { p.Algorithms = []string{"none"} }, func(p *oauth.ProviderProfile) { p.Algorithms = []string{"ES256", "ES256"} },
		func(p *oauth.ProviderProfile) { p.ResponseMode = "form_post" }, func(p *oauth.ProviderProfile) { p.PKCEMethod = "plain" },
		func(p *oauth.ProviderProfile) { p.NonceRequired = false }, func(p *oauth.ProviderProfile) { p.StateBytes = 64 },
		func(p *oauth.ProviderProfile) { p.NonceBytes = 0 }, func(p *oauth.ProviderProfile) { p.MaxCodeBytes = 0 },
		func(p *oauth.ProviderProfile) { p.MaxCodeBytes = 65537 }, func(p *oauth.ProviderProfile) { p.MaxTokenBytes = 0 },
		func(p *oauth.ProviderProfile) { p.MaxResponseBytes = 0 }, func(p *oauth.ProviderProfile) { p.Timeout = 0 },
		func(p *oauth.ProviderProfile) { p.ClockSkew = 0 },
	} {
		p := queryProfile()
		change(&p)
		requireQueryError(t, queryResponse("code=x"), p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		r, err := oauth.ParseQueryCallback(ctx, queryResponse("code=x"), queryProfile())
		r.Destroy()
		if err == nil {
			t.Fatal("invalid context admitted")
		}
		if ctx != nil && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation classification lost")
		}
	}
}

func TestQueryCallbackDenialStateLifetimeAndRedaction(t *testing.T) {
	ctx := context.Background()
	r, err := oauth.ParseQueryCallback(ctx, queryResponse("error=access_denied&error_description=private-description&error_uri=https%3A%2F%2Fprivate.example%2Ferror"), queryProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	if !r.Denied() {
		t.Fatal("provider denial not distinguished")
	}
	if _, ok := r.Input(); ok {
		t.Fatal("denial minted success custody")
	}
	alias := r
	var borrow []byte
	cause := errors.New("private-callback-error")
	err = r.UseDeniedState(ctx, func(_ context.Context, state []byte) error {
		borrow = state
		if string(state) != testNonce || cap(state) != len(state) {
			t.Fatal("wrong bounded state")
		}
		if err := alias.UseDeniedState(ctx, func(context.Context, []byte) error { t.Fatal("reentrant use admitted"); return nil }); err == nil {
			t.Fatal("reentrant use succeeded")
		}
		return cause
	})
	if !errors.Is(err, cause) || strings.Contains(fmt.Sprint(err), "private") {
		t.Fatal("borrow error leaked or lost classification")
	}
	for _, b := range borrow {
		if b != 0 {
			t.Fatal("denial borrow not cleared")
		}
	}
	for _, value := range []any{r, &r, alias, err} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			out := fmt.Sprintf(verb, value)
			for _, secret := range []string{testNonce, "private-description", "private.example", "private-callback-error"} {
				if strings.Contains(out, secret) {
					t.Fatal("denial diagnostic disclosure")
				}
			}
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("denial serialized")
	}
	if _, err := r.MarshalText(); err == nil {
		t.Fatal("denial text serialized")
	}
	if err := r.UseDeniedState(ctx, nil); err == nil {
		t.Fatal("nil consumer admitted")
	}
	var absentContext context.Context
	if err := r.UseDeniedState(absentContext, func(context.Context, []byte) error { t.Fatal("nil context admitted"); return nil }); err == nil {
		t.Fatal("nil context succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := r.UseDeniedState(canceled, func(context.Context, []byte) error { t.Fatal("canceled callback admitted"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if err := r.UseDeniedState(ctx, func(context.Context, []byte) error { panic("private-panic") }); err == nil || strings.Contains(fmt.Sprint(err), "private") {
		t.Fatal("panic escaped or leaked")
	}
	alias.Destroy()
	if err := r.UseDeniedState(ctx, func(context.Context, []byte) error { t.Fatal("destroyed state admitted"); return nil }); err == nil {
		t.Fatal("alias destruction not shared")
	}
	var zero oauth.QueryCallback
	zero.Destroy()
	if zero.Denied() {
		t.Fatal("zero result is denial")
	}
	if _, ok := zero.Input(); ok {
		t.Fatal("zero result has input")
	}
	if err := zero.UseDeniedState(ctx, func(context.Context, []byte) error { t.Fatal("zero result admitted"); return nil }); err == nil {
		t.Fatal("zero result succeeded")
	}
}

func TestQueryCallbackDenialConcurrentDestroy(t *testing.T) {
	r, err := oauth.ParseQueryCallback(context.Background(), queryResponse("error=extension_denial"), queryProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	entered, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := r.UseDeniedState(context.Background(), func(_ context.Context, state []byte) error {
			close(entered)
			<-release
			if string(state) != testNonce {
				t.Error("admitted borrow changed during destroy")
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	if err := r.UseDeniedState(context.Background(), func(context.Context, []byte) error { t.Error("concurrent borrow admitted"); return nil }); err == nil {
		t.Error("concurrent use succeeded")
	}
	r.Destroy()
	close(release)
	wg.Wait()
}

func TestQueryCallbackPreservesOriginalCode(t *testing.T) {
	code := " exact +/=:; code "
	raw := "code=" + url.QueryEscape(code) + "&state=" + testNonce + "&iss=https%3A%2F%2Fissuer.example"
	result, err := oauth.ParseQueryCallback(context.Background(), raw, queryProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer result.Destroy()
	input, ok := result.Input()
	if !ok || result.Denied() {
		t.Fatal("success did not retain original callback custody")
	}
	err = input.Use(context.Background(), func(_ context.Context, gotCode, gotState []byte) error {
		if string(gotCode) != code || string(gotState) != testNonce {
			t.Fatal("callback code or state changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Destroy()
	if err := input.Use(context.Background(), func(context.Context, []byte, []byte) error { t.Fatal("destroyed callback admitted"); return nil }); err == nil {
		t.Fatal("result destruction did not destroy original custody")
	}
}

func TestQueryCallbackPreservesCompleteCodeGrammar(t *testing.T) {
	code := make([]byte, 0x7f-0x20)
	for i := range code {
		code[i] = byte(i + 0x20)
	}
	p := queryProfile()
	p.MaxCodeBytes = len(code)
	r, err := oauth.ParseQueryCallback(context.Background(), queryResponse("code="+url.QueryEscape(string(code))), p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()
	input, ok := r.Input()
	if !ok {
		t.Fatal("valid code did not produce success")
	}
	if err := input.Use(context.Background(), func(_ context.Context, got, _ []byte) error {
		if string(got) != string(code) {
			t.Fatal("permitted code bytes were lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.UseDeniedState(context.Background(), func(context.Context, []byte) error { t.Fatal("success exposed denial state"); return nil }); err == nil {
		t.Fatal("success admitted denial use")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(verb, r), testNonce) {
			t.Fatal("success state disclosed")
		}
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("success serialized")
	}
}
