package identityhttp_test

import (
	"context"
	"fmt"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func ExampleRedirectGuard() {
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{
		Limits: identityhttp.Limits{MaximumHeaderBytes: 4096, MaximumURLBytes: 2048,
			MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 8},
		MaximumForwardedHops: 8, PublicHosts: []string{"login.example"},
	})
	if err != nil {
		panic(err)
	}
	guard, err := identityhttp.NewRedirectGuard(identityhttp.RedirectGuardConfig{
		Network: network, Targets: []string{"https://client.example/callback?view=compact"},
	})
	if err != nil {
		panic(err)
	}
	target, err := guard.Check(context.Background(), "https://client.example/callback?view=compact")
	fmt.Println(target, err)
	target, err = guard.Check(context.Background(), "https://client.example/callback?view=other")
	fmt.Println(target == "", err)
	// Output:
	// https://client.example/callback?view=compact <nil>
	// true identity.http.origin_denied
}
