package postgres

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProxyRetirementDiscoveryRejectsUnboundedPage(t *testing.T) {
	var invalid identity.InvalidInputError
	for _, request := range []ProxyRetirementDiscoveryRequest{
		{ScanLimit: 0}, {ScanLimit: 33}, {ScanLimit: 1, AfterFlowID: "not-a-flow"},
	} {
		if err := validateProxyRetirementDiscoveryRequest(request); !errors.As(err, &invalid) {
			t.Fatal("unbounded or malformed discovery request was accepted", err)
		}
	}
	for _, request := range []ProxyRetirementDiscoveryRequest{
		{ScanLimit: 1}, {ScanLimit: 32, AfterFlowID: "AgICAgICAgICAgICAgICAg"},
	} {
		if err := validateProxyRetirementDiscoveryRequest(request); err != nil {
			t.Fatal("bounded initial or continuing discovery was rejected", err)
		}
	}
}
