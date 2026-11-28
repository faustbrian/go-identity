package postgres

import "testing"

func TestProxyDisablePairRejectsUncomposedInputs(t *testing.T) {
	if op, err := NewProxyDisablePairOperator(&ProviderAuthorityOperator{}, &ProxyStartService{}, &ProxyPreviewService{}); op != nil || err == nil {
		t.Fatal("unconfigured services granted a proxy acknowledgement operator")
	}
	var op *ProxyDisablePairOperator
	if receipt, err := op.Acknowledge(t.Context(), ProxyCustodyFenceSealRequest{}); receipt != (ProxyDisablePairAcknowledgement{}) || err == nil {
		t.Fatal("an absent operator acknowledged cleanup")
	}
}
