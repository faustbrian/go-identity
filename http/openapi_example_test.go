package identityhttp_test

import (
	"context"
	"fmt"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func ExampleNewDocumentedHandler() {
	feature, err := identityhttp.NewProbeFeature(identityhttp.ProbeConfig{
		State:   func() identityhttp.ServerState { return identityhttp.ServerRunning },
		Timeout: time.Second,
		Readiness: identityhttp.ReadinessProvider{Check: func(context.Context) (identityhttp.ReadinessSnapshot, error) {
			return identityhttp.ReadinessSnapshot{Ready: true}, nil
		}},
	})
	if err != nil {
		panic(err)
	}
	handler, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		panic(err)
	}
	fmt.Println(handler != nil, len(document.Operations()))
	// Output: true 2
}
