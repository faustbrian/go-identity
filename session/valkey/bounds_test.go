package sessionvalkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEndpointAndTTLBounds(t *testing.T) {
	for _, endpoint := range []string{"", "redis://localhost:6379", "rediss://localhost", "rediss://localhost:0", "rediss://localhost:65536", "rediss://user:secret@localhost:6379", "rediss://localhost:6379/", "rediss://localhost:6379?", "rediss://localhost:6379#fragment", strings.Repeat("x", 2049)} {
		if _, _, err := parseEndpoint(endpoint); err == nil {
			t.Fatal("malformed endpoint accepted")
		}
	}
	for _, endpoint := range []string{"rediss://localhost:6379", "rediss://127.0.0.1:6379", "rediss://[::1]:6379"} {
		if address, name, err := parseEndpoint(endpoint); err != nil || address == "" || name == "" {
			t.Fatal("canonical endpoint denied", err)
		}
	}
	for _, duration := range []time.Duration{-1, 0, time.Millisecond - 1, 20*time.Second + 1} {
		if _, ok := milliseconds(duration); ok {
			t.Fatal("unbounded expiry accepted")
		}
	}
	if ttl, ok := milliseconds(1999 * time.Microsecond); !ok || ttl != "1" {
		t.Fatal("TTL rounded up")
	}
	if ttl, ok := milliseconds(20 * time.Second); !ok || ttl != "20000" {
		t.Fatal("maximum original TTL denied")
	}
}

func TestSecretsAndCheckpointRedact(t *testing.T) {
	material := bytes.Repeat([]byte("s"), 32)
	secret, err := NewSecret(material)
	if err != nil {
		t.Fatal(err)
	}
	material[0] = 'x'
	if secret.state.value[0] != 's' {
		t.Fatal("caller mutated key custody")
	}
	for _, value := range []any{secret, Config{Password: secret, NamespaceKey: secret}, Checkpoint{}, new(Cache)} {
		if text := fmt.Sprintf("%+v %#v %s", value, value, value); strings.Contains(text, strings.Repeat("s", 32)) {
			t.Fatal("secret formatting leak")
		}
	}
	if _, err = json.Marshal(secret); err == nil {
		t.Fatal("secret serialized")
	}
	if _, err = secret.MarshalText(); err == nil {
		t.Fatal("secret text serialized")
	}
	if _, err = json.Marshal(Checkpoint{}); err == nil {
		t.Fatal("checkpoint serialized")
	}
	if _, err = (Checkpoint{}).MarshalText(); err == nil {
		t.Fatal("checkpoint text serialized")
	}
	for _, size := range []int{0, 31, 4097} {
		if _, err = NewSecret(make([]byte, size)); err == nil {
			t.Fatal("secret size accepted")
		}
	}
	if ascii("", 1) || ascii("a b", 3) || ascii("\x00", 1) || ascii("é", 2) || ascii("ab", 1) || !ascii("a", 1) {
		t.Fatal("scope bounds changed")
	}
}

type panicClock struct{}

func (*panicClock) Now() time.Time { panic("private dependency diagnostic") }

func TestClockFailureDeniesWithoutPanic(t *testing.T) {
	var typedNil *panicClock
	for _, clock := range []*panicClock{typedNil, new(panicClock)} {
		c := &Cache{clock: clock}
		if !c.now().IsZero() {
			t.Fatal("broken trusted clock produced usable time")
		}
	}
}

func FuzzEndpoint(f *testing.F) {
	for _, seed := range []string{"rediss://localhost:6379", "REDISS://localhost:6379", "rediss://[::1]:6379", "redis://localhost:1", "rediss://u:p@localhost:9", "%"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		address, host, err := parseEndpoint(input)
		if err == nil {
			if len(input) > 2048 || !strings.HasPrefix(strings.ToLower(input), "rediss://") || address == "" || host == "" {
				t.Fatal("unbounded endpoint accepted")
			}
		}
	})
}
