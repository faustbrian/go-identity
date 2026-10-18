package phone_test

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-identity/phone"
)

func ExampleNumberPolicy() {
	p, err := phone.NewNumberPolicy(phone.NumberPolicySpec{
		Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64,
	})
	if err != nil {
		panic(err)
	}
	n, err := p.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		panic(err)
	}
	// Logging the opaque identifier is redacted. Project Record or DeliveryNumber
	// only at a deliberate PII persistence/transport boundary, not into logs.
	fmt.Println(n)
	record, err := n.Record()
	if err != nil {
		panic(err)
	}
	restored, err := p.Restore(context.Background(), record)
	if err != nil {
		panic(err)
	}
	fmt.Println(n.Equal(restored))
	// Output:
	// phone.Number(redacted)
	// true
}
