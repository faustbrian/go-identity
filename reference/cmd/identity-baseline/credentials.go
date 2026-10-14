package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

var errCredentials = errors.New("baseline: private local credentials unavailable or invalid")

// Each owner receives independent entropy. These keys are stable across
// restarts: regenerating request/replay custody would lose durable identities.
var credentialNames = []string{
	"request", "fingerprint", "risk-evidence", "risk-seal", "counter", "counter-replay",
	"otp-lockout", "preauth-cookie", "otp-wrap", "otp-attempt", "otp-code", "otp-intent",
	"identifier", "delivery-digest", "delivery-envelope", "delivery-namespace",
	"session-token", "session-csrf", "http-device", "http-rate", "capability-signing",
	"capability-replay", "capability-binding", "capability-envelope", "verification-scope",
	"signup-binding", "signup-intent", "password-flow", "signin-proof", "verification-http",
	"migration", "counter-envelope", "dummy-password",
}

type credentials struct {
	Version     int                 `json:"version"`
	Keys        map[string][32]byte `json:"keys"`
	Certificate string              `json:"certificate"`
	PrivateKey  string              `json:"privateKey"`
}

func (credentials) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "baseline credentials(redacted)")
}

func initializeCredentials(directory string, now time.Time) error {
	if err := os.Mkdir(directory, 0700); err != nil {
		return errCredentials
	}
	c := credentials{Version: 1, Keys: make(map[string][32]byte, len(credentialNames))}
	for _, name := range credentialNames {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return errCredentials
		}
		c.Keys[name] = key
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errCredentials
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return errCredentials
	}
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Identity baseline local capture"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		return errCredentials
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return errCredentials
	}
	c.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	encoded, err := json.Marshal(c)
	if err != nil {
		return errCredentials
	}
	path := filepath.Join(directory, "credentials.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errCredentials
	}
	_, writeErr := file.Write(encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		// This path was created exclusively by this invocation. An incomplete
		// credential file must not become restart custody.
		_ = os.Remove(path)
		return errCredentials
	}
	if syncDirectory(directory) != nil || syncDirectory(filepath.Dir(directory)) != nil {
		return errCredentials
	}
	return nil
}

// Stable filesystem custody needs the directory entry acknowledged as well as
// the file's content before initialization/provider handoff can report success.
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errCredentials
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return errCredentials
	}
	return nil
}

func loadCredentials(directory string, now time.Time) (credentials, error) {
	invalid := func() (credentials, error) { return credentials{}, errCredentials }
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return invalid()
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return invalid()
	}
	defer root.Close()
	before, err := root.Lstat("credentials.json")
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() < 1 || before.Size() > 32768 {
		return invalid()
	}
	file, err := root.Open("credentials.json")
	if err != nil {
		return invalid()
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
		return invalid()
	}
	decoder := json.NewDecoder(io.LimitReader(file, 32769))
	decoder.DisallowUnknownFields()
	var c credentials
	if err := decoder.Decode(&c); err != nil {
		return invalid()
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || c.Version != 1 || len(c.Keys) != len(credentialNames) {
		return invalid()
	}
	seen := make(map[[32]byte]bool, len(credentialNames))
	for _, name := range credentialNames {
		key := c.Keys[name]
		if key == ([32]byte{}) || seen[key] {
			return invalid()
		}
		seen[key] = true
	}
	pair, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil || len(pair.Certificate) != 1 {
		return invalid()
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) || !certificate.IsCA {
		return invalid()
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if certificate.VerifyHostname(host) != nil {
			return invalid()
		}
	}
	return c, nil
}
