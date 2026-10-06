package otp_test

import (
	"fmt"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/otp"
)

func ExampleVerifier() {
	// Synthetic keys/scope only. Production keys come from protected key custody,
	// and scope comes from the locked challenge and verified authorization.
	v, err := otp.NewVerifier(1, map[uint32][32]byte{1: {1}})
	if err != nil {
		panic("invalid example configuration")
	}
	destination, _ := otp.NewDestinationInput("user@example.test")
	scope, err := otp.NewDigestScope(otp.DigestScopeSpec{
		TenantID: "tenant", Purpose: otp.PurposeSignin, SubjectID: "subject",
		Channel: otp.ChannelEmail, Destination: destination, ChallengeID: "challenge",
		TargetID: "target", PolicyVersion: 1, Generation: 1, AuthorizationBinding: [32]byte{1},
	})
	if err != nil {
		panic("invalid example scope")
	}
	code, _ := auth.NewOneTimeCode("123456")
	digest, err := v.Digest(scope, code)
	if err != nil {
		panic("invalid example digest")
	}
	matched, err := v.Compare(scope, digest.Storage(), code)
	// A match confers no authority: counted durable attempt/expiry/reservation
	// and owning protected mutation must still commit atomically.
	fmt.Println(matched && err == nil)
	// Output: true
}
