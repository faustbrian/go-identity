package captchafox_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
	"github.com/faustbrian/go-identity/risk/captcha/captchafox"
)

func ExampleNew() {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	owner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		panic(err)
	}
	defer owner.Close()
	provider, err := captchafox.New(captchafox.Config{Endpoint: "https://api.captchafox.com/siteverify", UserAgent: "golib-example", Secret: []byte("synthetic-not-a-live-credential"), ResponseBytes: 4096, Profile: captcha.Config{Provider: "captchafox", API: "siteverify", Version: "2026-08-11", Tier: "free", APIProfile: "siteverify/free", SiteKey: "synthetic-configured-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, MaxTokenBytes: 8192, MaxConcurrent: 4, Timeout: time.Second, Lifetime: time.Minute, ChallengeMaxAge: 2 * time.Minute}}, owner, clock.System{})
	if err != nil {
		panic(err)
	}
	defer provider.Close(context.Background())
	// Complete issuer composition supplies the existing replay, policy, keys and
	// native executor; this constructor example performs no provider request.
	issuer := risk.CaptchaEvidenceIssuerConfig{Verify: provider.Observe}
	fmt.Println(issuer.Verify != nil)
	// Output: true
}
