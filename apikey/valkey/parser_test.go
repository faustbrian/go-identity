package apikeyvalkey

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestEndpointBoundsRejectCredentialsAndUnsupportedSyntax(t *testing.T) {
	for _, value := range []string{"", "redis://127.0.0.1:6379", "rediss://user:password@127.0.0.1:6379", "rediss://127.0.0.1:6379/", "rediss://127.0.0.1:6379?x=1", "rediss://127.0.0.1:6379#x", "rediss://127.0.0.1:0", "rediss://127.0.0.1:65536", strings.Repeat("x", 2049)} {
		if _, _, err := parseEndpoint(value); err == nil {
			t.Fatal("malformed endpoint admitted")
		}
	}
	for _, value := range []string{"rediss://127.0.0.1:6379", "rediss://localhost:6380", "rediss://[::1]:6379"} {
		if address, name, err := parseEndpoint(value); err != nil || address == "" || name == "" {
			t.Fatal("bounded TLS endpoint rejected")
		}
	}
}

func FuzzProjectionEndpoint(f *testing.F) {
	for _, seed := range []string{"rediss://127.0.0.1:6379", "rediss://[::1]:6379", "rediss://user:password@localhost:6379", "rediss://localhost:6379?x", "rediss://localhost:6379\x00", strings.Repeat("x", 2049)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		address, name, err := parseEndpoint(value)
		if err != nil {
			return
		}
		if len(value) > 2048 || !strings.HasPrefix(value, "rediss://") || name == "" {
			t.Fatal("endpoint parser accepted unbounded/unselected shape")
		}
		host, port, err := net.SplitHostPort(address)
		number, numberErr := strconv.Atoi(port)
		if err != nil || numberErr != nil || host != name || number < 1 || number > 65535 {
			t.Fatal("accepted endpoint lacks exact bounded host/port")
		}
	})
}
