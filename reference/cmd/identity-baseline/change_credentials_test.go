package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChangeCredentialsKeepOriginalBaselineAndRestartCustody(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	original, err := readPrivateFile(filepath.Join(directory, "credentials.json"), 32768)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadChangeCredentials(directory); err == nil {
		t.Fatal("serving invented missing change keys")
	}
	if err := prepareChangeCredentials(directory); err != nil {
		t.Fatal(err)
	}
	first, err := readPrivateFile(filepath.Join(directory, changeCredentialsName), 4096)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := prepareChangeCredentials(directory); err != nil {
			t.Fatal("exact selected initialization cannot resume", err)
		}
	}
	second, err := readPrivateFile(filepath.Join(directory, changeCredentialsName), 4096)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("selected key preparation regenerated original custody")
	}
	baseline, err := readPrivateFile(filepath.Join(directory, "credentials.json"), 32768)
	if err != nil || !bytes.Equal(original, baseline) {
		t.Fatal("change selection rewrote original baseline keys")
	}
	if _, err := loadCredentials(directory, time.Now()); err != nil {
		t.Fatal("additive selection invalidated the default baseline")
	}
	if err := os.Chmod(filepath.Join(directory, changeCredentialsName), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadChangeCredentials(directory); err == nil {
		t.Fatal("public-readable signing custody was accepted")
	}
	if err := prepareChangeCredentials(directory); err == nil {
		t.Fatal("unsafe existing custody was replaced")
	}
}

func TestChangeCredentialsDenyDuplicateJSONKeyCustody(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := prepareChangeCredentials(directory); err != nil {
		t.Fatal(err)
	}
	keys, err := loadChangeCredentials(directory)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readPrivateFile(filepath.Join(directory, changeCredentialsName), 4096)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := json.Marshal(keys["reauth-proof"])
	duplicate := append([]byte(`{"reauth-proof":`), key...)
	duplicate = append(duplicate, ',')
	duplicate = append(duplicate, raw[1:]...)
	if err := os.WriteFile(filepath.Join(directory, changeCredentialsName), duplicate, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadChangeCredentials(directory); err == nil {
		t.Fatal("ambiguous duplicate signing-key JSON accepted as stable custody")
	}
}
