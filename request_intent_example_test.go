package identity_test

import (
	"fmt"
	identity "github.com/faustbrian/go-identity"
)

func ExampleNewRequestIntent() {
	intent, err := identity.NewRequestIntent([]identity.FeatureField{
		{Name: "remember", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: false}},
		{Name: "expected.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}},
	})
	if err != nil {
		panic(err)
	}
	// Only the trusted adapter uses the owned projection; diagnostics stay redacted.
	fields, valid := intent.Fields()
	fmt.Println(valid, len(fields), intent)
	// Output: true 2 identity.RequestIntent(redacted)
}

func ExampleNewIdempotencyKey() {
	// The HTTP adapter supplies exactly one validated Idempotency-Key header;
	// direct API consumers construct the same opaque exact-byte value.
	key, err := identity.NewIdempotencyKey([]byte("example_retry_key"))
	if err != nil {
		panic(err)
	}
	fmt.Println(key)
	// Output: identity.IdempotencyKey(redacted)
}
