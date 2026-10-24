package passkeyhttp

import (
	"net/http/httptest"
	"testing"
)

func TestConditionalSigninRequiresExplicitDiscoveryAndNativeSupport(t *testing.T) {
	c, owner, flow, device := signinFixture(t)
	c.Conditional = true
	if _, err := NewSigninOptionsHandler(c); err == nil {
		t.Fatal("conditional presentation implicitly enabled discovery")
	}
	c.Discoverable = true
	if _, err := NewSigninOptionsHandler(c); err == nil {
		t.Fatal("conditional selection accepted a native owner without support")
	}
	c.Conditional = false
	h, err := NewSigninOptionsHandler(c)
	if err != nil {
		t.Fatal("existing discoverable implementation acquired a new requirement", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest("signin-options", `{"mode":"discoverable","flowID":"AAAAAAAAAAAAAAAAAAAAAQ"}`, flow, device))
	if w.Code != 403 || owner.options != 1 {
		t.Fatal("existing discoverable path acquired conditional behavior", w.Code)
	}
}
