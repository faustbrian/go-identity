package session_test

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/faustbrian/go-identity/session"
)

func ExampleToken() {
	// This is a standalone custody example, not authoritative session issuance.
	material := make([]byte, 32)
	rand.Read(material)
	key, err := session.NewDigestKey(1, material)
	if err != nil {
		panic(err)
	}
	clear(material)
	token, err := session.NewToken(32)
	if err != nil {
		panic(err)
	}
	digest, err := token.Digest(key, "tenant-example")
	if err != nil {
		panic(err)
	}
	fmt.Println(digest.KeyVersion)
	copy := token
	// In real issuance this disclosure must follow authoritative commitment.
	wire, err := token.Reveal()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(wire)) // Never print the bearer itself.
	_, err = copy.Reveal()
	fmt.Println(errors.Is(err, session.ErrTokenAlreadyRevealed))
	// Output:
	// 1
	// 43
	// true
}
