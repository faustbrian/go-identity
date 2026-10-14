package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrivateConfigurationInitializationAndCustody(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	now := time.Now()
	if err := initializeCredentials(directory, now); err != nil {
		t.Fatal("private initialization failed", err)
	}
	first, err := loadCredentials(directory, now)
	if err != nil {
		t.Fatal("private configuration rejected", err)
	}
	second, err := loadCredentials(directory, now)
	if err != nil || first.Keys["request"] != second.Keys["request"] {
		t.Fatal("restart changed durable credential custody")
	}
	if err := initializeCredentials(directory, now); err == nil {
		t.Fatal("initialization overwrote an existing directory")
	}
	for _, name := range credentialNames {
		if first.Keys[name] == ([32]byte{}) {
			t.Fatal("missing private key")
		}
		for _, other := range credentialNames {
			if name != other && first.Keys[name] == first.Keys[other] {
				t.Fatal("different owners share a generated key")
			}
		}
	}
	pair, err := tls.X509KeyPair([]byte(first.Certificate), []byte(first.PrivateKey))
	if err != nil {
		t.Fatal("generated TLS pair rejected")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal("generated TLS certificate rejected")
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := certificate.VerifyHostname(host); err != nil {
			t.Fatal("missing loopback certificate identity")
		}
	}
	if err := certificate.VerifyHostname("public.example"); err == nil {
		t.Fatal("local certificate authenticates a public host")
	}
	if _, err := loadCredentials(directory, now.Add(31*24*time.Hour)); err == nil {
		t.Fatal("expired TLS configuration accepted")
	}
	path := filepath.Join(directory, "credentials.json")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(directory, now); err == nil {
		t.Fatal("public-readable credentials accepted")
	}
}

func TestPrivateCredentialsCannotBeDisclosedByFormatting(t *testing.T) {
	secrets := credentials{PrivateKey: "synthetic-private-key-material", Keys: map[string][32]byte{"request": {9}}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if rendered := fmt.Sprintf(verb, secrets); strings.Contains(rendered, "synthetic-private-key-material") || strings.Contains(rendered, "request") {
			t.Fatal("private credentials disclosed through formatting")
		}
	}
}

func TestPrivateConfigurationRejectsSymlinkAndUnknownInput(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	now := time.Now()
	if err := initializeCredentials(directory, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "credentials.json")
	if err := os.Rename(path, filepath.Join(directory, "other.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other.json", path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(directory, now); err == nil {
		t.Fatal("symlinked credential input accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"unexpected":"redacted"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentials(directory, now); err == nil {
		t.Fatal("unknown credential configuration accepted")
	}
}
