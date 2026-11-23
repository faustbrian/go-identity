package ssohttp

import (
	"errors"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestSAMLIDPSelectionRejectsMissingConfiguration(t *testing.T) {
	op, err := NewSAMLIDPInitiatedOperation(SAMLIDPSigninConfig{})
	if !errors.Is(err, identityhttp.ErrInvalidInput) || op.Handler != nil {
		t.Fatal("unsolicited SAML exposed a handler without explicit configuration", err)
	}
}
