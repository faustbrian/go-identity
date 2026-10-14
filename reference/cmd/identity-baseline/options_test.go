package main

import (
	"net"
	"testing"
)

func TestLocalCaptureRequiresExplicitLoopbackSelection(t *testing.T) {
	valid := []string{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://127.0.0.1:8443"}
	if _, err := parseOptions(valid); err != nil {
		t.Fatal("explicit local profile rejected", err)
	}
	for _, args := range [][]string{
		{"serve", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://127.0.0.1:8443"},
		{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "http://127.0.0.1:8443"},
		{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://0.0.0.0:8443"},
		{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://public.example:8443"},
		{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://user:secret@localhost:8443"},
		{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://localhost:8443/path"},
		{"serve", "--local-capture", "--directory", "private-run", "--dsn-file", "private-dsn", "--origin", "https://localhost:8443", "extra"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Fatal("unsafe or implicit profile accepted")
		}
	}
}

func FuzzLocalProfileNeverSelectsPublicListener(f *testing.F) {
	for _, seed := range []string{"https://localhost:8443", "https://127.0.0.1:8443", "https://[::1]:8443", "https://0.0.0.0:8443", "http://public.example:443", "https://localhost:8443/path", "https://user:private@localhost:8443"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, origin string) {
		o, err := parseOptions([]string{"serve", "--local-capture", "--directory", "private", "--dsn-file", "private-dsn", "--origin", origin})
		if err != nil {
			return
		}
		host, _, err := net.SplitHostPort(o.address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			t.Fatal("selected listener is not literal loopback")
		}
	})
}
