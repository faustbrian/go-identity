package otp_test

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-identity/otp"
)

func ExampleCodeProfile_Generate() {
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{
		Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6,
		TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5,
		Attempts: 5, Replacement: otp.ReplacePrevious,
	})
	if err != nil {
		panic("invalid profile")
	}
	var length int
	err = profile.Generate(context.Background(), func(_ context.Context, borrowed []byte) error {
		// Real issuance computes the keyed scoped digest and encrypted delivery
		// intent here, without retaining or printing these borrowed bytes.
		length = len(borrowed)
		return nil
	})
	if err != nil {
		panic("generation failed")
	}
	fmt.Println(length)
	// Output: 6
}
