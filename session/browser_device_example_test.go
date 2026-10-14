package session_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/faustbrian/go-identity/session"
)

func ExampleNewBrowserDeviceCodec() {
	// Real deployments retain and distribute dedicated keys securely; do not
	// generate a new key on each request or process restart.
	var material [32]byte
	rand.Read(material[:])
	key, err := session.NewBrowserDeviceKey(1, material[:])
	if err != nil {
		panic(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		panic(err)
	}
	codec, err := session.NewBrowserDeviceCodec(session.BrowserDeviceConfig{Namespace: "example-environment", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: cookie})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	issued, err := codec.Issue(ctx, now, "tenant-a", "https://tenant.example")
	if err != nil {
		panic(err)
	}
	// The HTTP owner delivers this only via a secure no-store Set-Cookie,
	// then strictly acquires one original cookie on the next request.
	header, err := http.ParseSetCookie(issued.CookieHeader())
	if err != nil {
		panic(err)
	}
	observed, err := codec.Resolve(ctx, now.Add(time.Minute), "tenant-a", "https://tenant.example", header.Value)
	if err != nil {
		panic(err)
	}
	fmt.Println(observed.DeviceID() == issued.DeviceID(), observed.ExpiresAt() == issued.ExpiresAt(), observed.CookieHeader() == "")
	// Output: true true true
}
