package otp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// SEND-01/03/08/10: public callers select one possession variant, never an
// execution proof. A platform service, not consumers, owns the workflow.
func TestPublicSendFlowRetainsDisjointPossession(t *testing.T) {
	bearer := auth.NewBearerCredential(strings.Repeat("A", 43))
	id, err := identity.ParsePreAuthTransactionID("AAAAAAAAAAAAAAAAAAAAAQ")
	if err != nil {
		t.Fatal(err)
	}
	preauth, err := otp.NewPreAuthSendFlow(id, bearer)
	if err != nil {
		t.Fatal(err)
	}
	kind, flowID, credential, err := preauth.Bindings()
	if err != nil || kind != otp.FlowAuthorizationPreAuthTransaction || flowID != string(id) || credential.Token() != bearer.Token() {
		t.Fatal("preauth possession lost", err)
	}
	session, err := otp.NewSessionSendFlow("original-session", bearer)
	if err != nil {
		t.Fatal(err)
	}
	kind, flowID, credential, err = session.Bindings()
	if err != nil || kind != otp.FlowAuthorizationAuthenticatedSession || flowID != "original-session" || credential.Token() != bearer.Token() {
		t.Fatal("session possession lost", err)
	}
	for _, flow := range []otp.SendFlow{preauth, session} {
		if strings.Contains(fmt.Sprintf("%+v %#v", flow, flow), bearer.Token()) {
			t.Fatal("diagnostic bearer leak")
		}
		if _, err := json.Marshal(flow); err == nil {
			t.Fatal("possession serialized")
		}
	}
	if _, _, _, err := (otp.SendFlow{}).Bindings(); err == nil {
		t.Fatal("zero variant accepted")
	}
	if _, err := otp.NewSessionSendFlow("bad session", bearer); err == nil {
		t.Fatal("invalid session id accepted")
	}
	if _, err := otp.NewSessionSendFlow("session", auth.BearerCredential{}); err == nil {
		t.Fatal("missing bearer accepted")
	}
}

// Compile the complete public method vocabulary in an external consumer. No
// PostgreSQL coordinator or private command/preparation types appear here.
func usePublicSend(ctx context.Context, service otp.Service, request otp.SendRequest) (otp.SendResult, error) {
	return service.Send(ctx, request)
}

// All caller-owned collections must be bounded before a durable adapter clones
// the context; authorization's structural validator does not own these limits.
func TestPublicSendBoundsCallerCollectionsBeforeClone(t *testing.T) {
	flow, err := otp.NewSessionSendFlow("original-session", auth.NewBearerCredential(strings.Repeat("A", 43)))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := otp.NewDestinationInput("person@example.test")
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("bounded-send"))
	if err != nil {
		t.Fatal(err)
	}
	base := otp.SendRequest{TenantID: "tenant", UserID: "user", Flow: flow,
		Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{
			Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"},
			Action: "identity.otp.send", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.otp.send"}}},
		Channel: otp.ChannelEmail, Destination: destination, Purpose: otp.PurposeSignin,
		TargetID: "signin", Network: "192.0.2.8", Device: "device", IdempotencyKey: key}
	if err := base.Validate(); err != nil {
		t.Fatal("valid fixture rejected", err)
	}
	for _, size := range []int{64, 65} {
		attrs := make(authorization.Attributes, size)
		groups := make([]authorization.SubjectID, size)
		for i := range size {
			attrs[authorization.AttributeName(fmt.Sprintf("attribute-%d", i))] = authorization.StringValue("value")
			groups[i] = authorization.SubjectID(fmt.Sprintf("group-%d", i))
		}
		for _, field := range []string{"request", "subject", "resource", "environment", "groups"} {
			r := base
			switch field {
			case "request":
				r.Caller.Request.Attributes = attrs
			case "subject":
				r.Caller.Request.Subject.Attributes = attrs
			case "resource":
				r.Caller.Request.Resource.Attributes = attrs
			case "environment":
				r.Caller.Request.Environment.Attributes = attrs
			case "groups":
				r.Caller.Request.Subject.Groups = groups
			}
			if err := r.Validate(); (err != nil) != (size > 64) {
				t.Fatalf("%s count=%d: expected invalid=%v, got %v", field, size, size > 64, err)
			}
		}
	}
}
