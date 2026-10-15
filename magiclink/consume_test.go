package magiclink_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identity/magiclink"
)

func TestConsumeInputPreservesOpaqueProofAndBrowserScope(t *testing.T) {
	s, p, _, _ := inspectionFixture(t)
	proof, _, err := s.Issue(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	request := requestInput(t)
	request.Caller.Request.Action = "identity.magic-link.consume"
	r := magiclink.ConsumeRequest{TenantID: request.TenantID, CommandID: request.CommandID, Token: proof, Callback: request.Callback, PreAuthID: request.PreAuthID, Cookie: request.Cookie, Caller: request.Caller, Origin: request.Origin, Network: request.Network, Device: request.Device}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), proof, "identity.magic-link.consume", "identity"); err != nil {
		t.Fatal("validation consumed/transferred original proof", err)
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("consuming input serialized")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "example.test") {
		t.Fatal("consuming diagnostics exposed scope")
	}
	for name, change := range map[string]func(*magiclink.ConsumeRequest){"missing-proof": func(r *magiclink.ConsumeRequest) { r.Token = capability.Proof{} }, "missing-browser": func(r *magiclink.ConsumeRequest) { r.Cookie = auth.BearerCredential{} }, "missing-flow": func(r *magiclink.ConsumeRequest) { r.PreAuthID = "" }, "foreign-tenant": func(r *magiclink.ConsumeRequest) { r.Caller.Request.Tenant = "foreign" }, "wrong-purpose": func(r *magiclink.ConsumeRequest) { r.Caller.Request.Action = "identity.magic-link.request" }, "fragment": func(r *magiclink.ConsumeRequest) { r.Callback += "#" }} {
		t.Run(name, func(t *testing.T) {
			bad := r
			bad.Caller = r.Caller.Clone()
			change(&bad)
			if bad.Validate() == nil {
				t.Fatal("malformed consume input accepted")
			}
		})
	}
}
