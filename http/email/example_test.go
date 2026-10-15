package emailhttp_test

import (
	"context"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
)

func ExampleNewConfirmationFeature() {
	// Deployment supplies native owners/configuration, not domain handlers.
	compose := func(config emailhttp.ConfirmationConfig) (http.Handler, error) {
		feature, err := emailhttp.NewConfirmationFeature(config)
		if err != nil {
			return nil, err
		}
		handler, _, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		return handler, err
	}
	_ = compose
}

func ExampleNewManagedConfirmationFeature() {
	// Supply the native management owner and strict shared rate limiter.
	compose := func(config emailhttp.ManagedConfirmationConfig) (http.Handler, error) {
		feature, err := emailhttp.NewManagedConfirmationFeature(config)
		if err != nil {
			return nil, err
		}
		handler, _, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Managed email", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		return handler, err
	}
	_ = compose
}
