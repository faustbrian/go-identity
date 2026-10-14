package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const changeCredentialsName = "password-change-credentials.json"

var changeCredentialNames = []string{"reauth-proof", "reauth-identifier", "change-intent"}

// Additive private custody never rewrites the baseline's original keys. Only
// explicit init/migrate selection creates it; serving cannot invent new keys.
func prepareChangeCredentials(directory string) error {
	if _, err := loadChangeCredentials(directory); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errCredentials
	}
	keys := make(map[string][32]byte, len(changeCredentialNames))
	for _, name := range changeCredentialNames {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return errCredentials
		}
		keys[name] = key
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return errCredentials
	}
	defer clear(raw)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return errCredentials
	}
	defer root.Close()
	file, err := root.OpenFile(changeCredentialsName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		_, err = loadChangeCredentials(directory)
		return err
	}
	if err != nil {
		return errCredentials
	}
	_, writeErr := file.Write(raw)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || syncRootDirectory(root) != nil {
		return errCredentials
	}
	return nil
}

func loadChangeCredentials(directory string) (map[string][32]byte, error) {
	path := filepath.Join(directory, changeCredentialsName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	raw, err := readPrivateFile(path, 4096)
	if err != nil {
		return nil, errCredentials
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var keys map[string][32]byte
	var extra any
	if decoder.Decode(&keys) != nil || decoder.Decode(&extra) != io.EOF || len(keys) != len(changeCredentialNames) {
		return nil, errCredentials
	}
	canonical, err := json.Marshal(keys)
	if err != nil || !bytes.Equal(raw, canonical) {
		clear(canonical)
		return nil, errCredentials
	}
	clear(canonical)
	seen := make(map[[32]byte]bool)
	for _, name := range changeCredentialNames {
		value := keys[name]
		if value == ([32]byte{}) || seen[value] {
			return nil, errCredentials
		}
		seen[value] = true
	}
	// Re-entry acknowledges original content and directory, even after a
	// previous creation returned an uncertain filesystem result.
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errCredentials
	}
	defer root.Close()
	file, err := root.Open(changeCredentialsName)
	if err != nil {
		return nil, errCredentials
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil || syncRootDirectory(root) != nil {
		return nil, errCredentials
	}
	return keys, nil
}
