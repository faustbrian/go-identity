package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
)

func TestSAMLStartRequestKeyScopeCannotAdmitOtherGETs(t *testing.T) {
	scope := RequestKeyScope{
		TenantID: "tenant", ActorID: "sso-service", ActorKind: authorization.SubjectServiceAccount,
		Method: "GET", RouteID: SSOSAMLSigninStartOperation().OperationID,
	}
	if !validRequestKeyScope(scope) {
		t.Fatal("exact native SAML start GET was rejected")
	}
	foreign := scope
	foreign.RouteID = SSOOAuth2SigninStartOperation().OperationID
	if validRequestKeyScope(foreign) {
		t.Fatal("SAML start exception admitted another GET route")
	}
	foreign = scope
	foreign.ActorKind = authorization.SubjectUser
	if validRequestKeyScope(foreign) {
		t.Fatal("SAML start exception admitted a user-owned request scope")
	}
	foreign = scope
	foreign.Method = "POST"
	if validRequestKeyScope(foreign) {
		t.Fatal("SAML start could also allocate through a POST scope")
	}
	legacy := &Coordinator{}
	if legacy.acceptsRequestKeyMethod("GET", false) {
		t.Fatal("legacy client keys admitted a GET")
	}
}
