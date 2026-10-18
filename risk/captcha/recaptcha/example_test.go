package recaptcha_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/captcha"
	"github.com/faustbrian/go-identity/risk/captcha/recaptcha"
)

func ExampleNew() {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	owner, err := httpclient.New(httpclient.Config{Transport: transport})
	if err != nil {
		panic(err)
	}
	defer owner.Close()
	provider, err := recaptcha.New(recaptcha.Config{Endpoint: "https://www.google.com/recaptcha/api/siteverify", UserAgent: "golib-example", Secret: []byte("synthetic-not-a-live-credential"), ResponseBytes: 4096, Profile: captcha.Config{Provider: "recaptcha", API: "classic_siteverify", Version: "v3", Tier: "standard", APIProfile: "classic_siteverify/v3", SiteKey: "synthetic-configured-site", ConfigurationVersion: "synthetic-v1", Hostnames: []string{"example.com"}, ExpectedAction: "account/signup", MaxTokenBytes: 8192, MaxConcurrent: 4, Timeout: time.Second, Lifetime: time.Minute, ChallengeMaxAge: 2 * time.Minute}}, owner, clock.System{})
	if err != nil {
		panic(err)
	}
	defer provider.Close(context.Background())
	// Complete issuer composition additionally supplies its existing replay,
	// policy, keys and native executor. This example performs no provider IO.
	issuerConfig := risk.CaptchaEvidenceIssuerConfig{Verify: provider.Observe}
	fmt.Println(issuerConfig.Verify != nil)
	// Output: true
}
