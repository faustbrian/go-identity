package apikey

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestOrganizationProjectionPreservesOriginalUserRecordEncoding(t *testing.T) {
	// This exact pre-extension shape is the stored USER ciphertext plaintext.
	// A zero organization arm must remain omitted, not rewrite accepted entries.
	type originalUserRecord struct {
		Schema                    uint16
		Lookup                    projectionLookupRecord
		Grant                     []string
		ReadStartedAt, ValidUntil time.Time
		AttemptID                 VerificationAttemptID
		State                     VerificationAttemptState
		Quota                     *QuotaMetadata `json:",omitempty"`
	}
	user, err := json.Marshal(originalUserRecord{Schema: 1, Grant: []string{"invoice.read"}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := json.Marshal(positiveProjectionRecord{Schema: 1, Grant: []string{"invoice.read"}})
	if err != nil || !bytes.Equal(user, current) {
		t.Fatal("unselected organization arm changed original USER record bytes", err)
	}
}
