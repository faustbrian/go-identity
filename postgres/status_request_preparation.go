package postgres

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	identity "github.com/faustbrian/go-identity"
)

func sealAdminStatusVersions(key [32]byte, binding RequestKeyPreparationBinding, version, authority uint64) ([]byte, error) {
	if !usableStatusVersion(version) || !usableStatusVersion(authority) {
		return nil, identity.UnavailableError{}
	}
	aead, err := statusVersionCipher(key, binding.Admission.CommandID)
	if err != nil {
		return nil, err
	}
	var pair [16]byte
	binary.BigEndian.PutUint64(pair[:8], version)
	binary.BigEndian.PutUint64(pair[8:], authority)
	return aead.Seal(nil, nil, pair[:], statusVersionAAD(binding)), nil
}

func openAdminStatusVersions(key [32]byte, binding RequestKeyPreparationBinding, sealed []byte) (uint64, uint64, error) {
	aead, err := statusVersionCipher(key, binding.Admission.CommandID)
	if err != nil || len(sealed) != 16+aead.Overhead() {
		return 0, 0, identity.UnavailableError{}
	}
	pair, err := aead.Open(nil, nil, sealed, statusVersionAAD(binding))
	if err != nil || len(pair) != 16 {
		return 0, 0, identity.UnavailableError{}
	}
	version, authority := binary.BigEndian.Uint64(pair[:8]), binary.BigEndian.Uint64(pair[8:])
	if !usableStatusVersion(version) || !usableStatusVersion(authority) {
		return 0, 0, identity.UnavailableError{}
	}
	return version, authority, nil
}

func statusVersionCipher(key [32]byte, command identity.CommandID) (cipher.AEAD, error) {
	if _, err := identity.ParseCommandID(string(command)); err != nil || key == ([32]byte{}) {
		return nil, identity.UnavailableError{}
	}
	// Use the original mapping key revision and a command-specific subkey. This
	// separates encryption from fingerprints and limits nonce use to one command.
	derive := hmac.New(sha256.New, key[:])
	_, _ = derive.Write([]byte("golib.identity.admin-status-versions.v1\x00"))
	_, _ = derive.Write([]byte(command))
	derived := derive.Sum(nil)
	block, err := aes.NewCipher(derived)
	clear(derived)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func statusVersionAAD(b RequestKeyPreparationBinding) []byte {
	feature := requestPreparationIdentity(b.Feature)
	return cborMap(map[string][]byte{
		"namespace": cborText(b.Namespace), "policy": cborUint(b.PolicyVersion),
		"tenant": cborText(string(b.Scope.TenantID)), "actor": cborText(string(b.Scope.ActorID)),
		"actor_kind": cborText(string(b.Scope.ActorKind)), "method": cborText(b.Scope.Method), "route": cborText(b.Scope.RouteID),
		"command": cborText(string(b.Admission.CommandID)), "key_version": cborUint(uint64(b.Admission.FingerprintKeyVersion)),
		"intent": cborBytes(b.IntentDigest[:]), "preparation": cborBytes(feature[:]),
	})
}

func usableStatusVersion(version uint64) bool { return version != 0 && version != ^uint64(0) }
