package reference

import "testing"

func TestReferenceSAMLIDPSelectionRequiresManagedProvider(t *testing.T) {
	config := StoreConfiguration{HTTPEnterpriseSAML: &HTTPEnterpriseSAMLConfiguration{IDPInitiated: true}}
	if err := validateEnterpriseSAMLSelection(config); err == nil {
		t.Fatal("unsolicited HTTP selection without a managed SAML provider was admitted")
	}
}
