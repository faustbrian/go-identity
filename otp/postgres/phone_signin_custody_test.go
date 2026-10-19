package postgres

import (
	"bytes"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPhoneSigninRecipientFrameRetainsExactStoredProfile(t *testing.T) {
	_, _, _, _, original, _ := signinMappingFixture(t)
	recipient := *original.recipient
	recipient.Query.Kind, recipient.Identifier.Kind = identity.IdentifierPhone, identity.IdentifierPhone
	recipient.Query.CanonicalValue, recipient.Identifier.CanonicalValue = "+12025550123", "+12025550123"
	recipient.Query.NormalizationProfile = "identity.phone.e164-ascii-v1.metadata-v9.0.40"
	recipient.Query.NormalizationVersion = 1
	recipient.Identifier.NormalizationProfile = recipient.Query.NormalizationProfile
	recipient.Identifier.NormalizationVersion = recipient.Query.NormalizationVersion
	if err := recipient.Validate(); err != nil {
		t.Fatal("profile-bound phone fixture invalid", err)
	}
	wire := appendSendRecipient(nil, recipient)
	reader := recordReader{data: wire, ok: true}
	restored, err := readSendRecipient(&reader)
	if err != nil || len(reader.data) != 0 || !reflect.DeepEqual(recipient, restored) {
		t.Fatal("original phone recipient custody discarded stored comparison profile", err)
	}
	if !bytes.Equal(wire, appendSendRecipient(nil, restored)) {
		t.Fatal("profile-bound recipient frame is noncanonical")
	}
	for i := range wire {
		reader := recordReader{data: wire[:i], ok: true}
		if _, err := readSendRecipient(&reader); err == nil && reader.ok && len(reader.data) == 0 {
			t.Fatal("truncated profile-bound recipient accepted")
		}
	}
}
