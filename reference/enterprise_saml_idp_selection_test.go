package reference

import "testing"

func TestReferenceSAMLIDPSelectionRequiresManagedProvider(t *testing.T) {
	config := StoreConfiguration{HTTPEnterpriseSAML: &HTTPEnterpriseSAMLConfiguration{IDPInitiated: true}}
	if err := validateEnterpriseSAMLSelection(config); err == nil {
		t.Fatal("unsolicited HTTP selection without a managed SAML provider was admitted")
	}
}

func TestReferenceSAMLLogoutMatchKeysAreDedicated(t *testing.T) {
	stateKey := [32]byte{1}
	confirmationKey := [32]byte{2}
	config := EnterpriseSAMLConfiguration{
		IDPInitiated: &EnterpriseSAMLIDPConfiguration{ConfirmationKeys: map[uint32][32]byte{1: confirmationKey}},
		Logout: &EnterpriseSAMLLogoutConfiguration{
			CurrentMatchKey: 1, MatchKeys: map[uint32][32]byte{1: {3}},
		},
	}
	config.Login.StateKeys = map[uint32][32]byte{1: stateKey}
	if _, err := newEnterpriseSAMLLogoutCustody(config, "test-envelope"); err != nil {
		t.Fatal("dedicated logout match keys rejected", err)
	}
	for _, reused := range [][32]byte{stateKey, confirmationKey} {
		config.Logout.MatchKeys[1] = reused
		if _, err := newEnterpriseSAMLLogoutCustody(config, "test-envelope"); err == nil {
			t.Fatal("existing browser key was accepted as a logout match key")
		}
	}
}
