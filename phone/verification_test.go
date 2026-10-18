package phone_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/phone"
)

func enrollmentRequest(t *testing.T) phone.EnrollmentRequestSpec {
	t.Helper()
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	number, err := policy.Canonicalize(context.Background(), "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-phone-request"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	return phone.EnrollmentRequestSpec{TenantID: "tenant", UserID: "user", Number: number,
		Session:        auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"),
		Proof:          auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant", Subject: "user", Purpose: "identity.password.verify", Audience: "phone", Method: "password", Assurance: auth.AssuranceSingleFactor, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}, SessionID: "original-session", SessionVersion: 1, Action: "identity.phone.send-verification"},
		Caller:         authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user"}, Action: "identity.phone.send-verification", Resource: authorization.Resource{Type: "identity.user", ID: "user"}}},
		IdempotencyKey: key, Network: "192.0.2.1", Device: "original-device"}
}

func TestEnrollmentRequestValidatesSelfActionAndBoundedOriginalInput(t *testing.T) {
	r := enrollmentRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("bearer request must not require CSRF", err)
	}
	for name, mutate := range map[string]func(*phone.EnrollmentRequestSpec){
		"tenant": func(r *phone.EnrollmentRequestSpec) { r.TenantID = "foreign" },
		"invalid-tenant": func(r *phone.EnrollmentRequestSpec) {
			r.TenantID = "bad tenant"
			r.Caller.Request.Tenant = "bad tenant"
		},
		"user":  func(r *phone.EnrollmentRequestSpec) { r.UserID = "foreign" },
		"actor": func(r *phone.EnrollmentRequestSpec) { r.Caller.Request.Subject.ID = "foreign" },
		"service": func(r *phone.EnrollmentRequestSpec) {
			r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount
		},
		"action":         func(r *phone.EnrollmentRequestSpec) { r.Caller.Request.Action = "identity.phone.verify" },
		"policy":         func(r *phone.EnrollmentRequestSpec) { r.Caller.PolicyRevision = 0 },
		"number":         func(r *phone.EnrollmentRequestSpec) { r.Number = phone.Number{} },
		"session":        func(r *phone.EnrollmentRequestSpec) { r.Session = auth.BearerCredential{} },
		"proof-user":     func(r *phone.EnrollmentRequestSpec) { r.Proof.Proof.Subject = "foreign" },
		"proof-tenant":   func(r *phone.EnrollmentRequestSpec) { r.Proof.Proof.Tenant = "foreign" },
		"proof-action":   func(r *phone.EnrollmentRequestSpec) { r.Proof.Action = "identity.phone.verify" },
		"proof-session":  func(r *phone.EnrollmentRequestSpec) { r.Proof.SessionVersion = 0 },
		"proof-time":     func(r *phone.EnrollmentRequestSpec) { r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt },
		"key":            func(r *phone.EnrollmentRequestSpec) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"network":        func(r *phone.EnrollmentRequestSpec) { r.Network = "localhost" },
		"zone":           func(r *phone.EnrollmentRequestSpec) { r.Network = "fe80::1%en0" },
		"noncanonical":   func(r *phone.EnrollmentRequestSpec) { r.Network = "2001:0db8::1" },
		"device-empty":   func(r *phone.EnrollmentRequestSpec) { r.Device = "" },
		"device-large":   func(r *phone.EnrollmentRequestSpec) { r.Device = strings.Repeat("x", 129) },
		"device-control": func(r *phone.EnrollmentRequestSpec) { r.Device = "device\n" },
		"device-utf8":    func(r *phone.EnrollmentRequestSpec) { r.Device = string([]byte{255}) },
		"collections": func(r *phone.EnrollmentRequestSpec) {
			r.Caller.Request.Subject.Groups = make([]authorization.SubjectID, 65)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r
			candidate.Caller = r.Caller.Clone()
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid original enrollment admitted")
			}
			if _, err := phone.NewEnrollmentRequest(candidate); err == nil {
				t.Fatal("constructor admitted invalid enrollment")
			}
		})
	}
}

func verificationRequest(t *testing.T) phone.VerificationRequestSpec {
	t.Helper()
	r := enrollmentRequest(t)
	flow, err := otp.NewSessionSendFlow("original-session", r.Session)
	if err != nil {
		t.Fatal(err)
	}
	send, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	r.Caller.Request.Action = "identity.phone.verify"
	return phone.VerificationRequestSpec{TenantID: r.TenantID, UserID: r.UserID, Caller: r.Caller, Flow: flow, SendCommandID: send, Code: code}
}

func TestPhoneVerificationRequiresOriginalAuthenticatedSessionScope(t *testing.T) {
	r := verificationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*phone.VerificationRequestSpec){
		"send":      func(r *phone.VerificationRequestSpec) { r.SendCommandID = "invalid" },
		"zero-flow": func(r *phone.VerificationRequestSpec) { r.Flow = otp.SendFlow{} },
		"tenant":    func(r *phone.VerificationRequestSpec) { r.TenantID = "foreign" },
		"user":      func(r *phone.VerificationRequestSpec) { r.UserID = "foreign" },
		"action":    func(r *phone.VerificationRequestSpec) { r.Caller.Request.Action = "identity.phone.signin" },
		"preauth": func(r *phone.VerificationRequestSpec) {
			id, err := identity.NewPreAuthTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			flow, err := otp.NewPreAuthSendFlow(id, enrollmentRequest(t).Session)
			if err != nil {
				t.Fatal(err)
			}
			r.Flow = flow
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := r
			candidate.Caller = r.Caller.Clone()
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("foreign verification scope admitted")
			}
			if _, err := phone.NewVerificationRequest(candidate); err == nil {
				t.Fatal("constructor admitted invalid verification")
			}
		})
	}
	// The opaque code has no structural accessor. Native attempt issuance owns
	// code validity and metering, as for the existing OTP completion contract.
	r.Code = auth.OneTimeCode{}
	if r.Validate() != nil {
		t.Fatal("core invented opaque code inspection")
	}
}

func phoneRecovery(t *testing.T, r phone.VerificationRequestSpec) phone.VerificationRecovery {
	t.Helper()
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := phone.NewVerificationRecovery(otp.CheckRecoveryBindings{SendCommandID: r.SendCommandID, Attempt: otp.AttemptRecoveryIdentity{TenantID: r.TenantID, CommandID: command, AttemptID: "AQEBAQEBAQEBAQEBAQEBAQ", Fingerprint: otp.AttemptFingerprint(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))), FingerprintKeyVersion: 1}, ExpectedVersion: 1, DigestKeyVersion: 1, ScopeDigest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	return recovery
}

func TestPhoneRecoveryRetainsCodeFreeOriginalAttemptWithoutAlias(t *testing.T) {
	r := verificationRequest(t)
	recovery := phoneRecovery(t, r)
	b, err := recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if b.SendCommandID != r.SendCommandID || b.Attempt.TenantID != r.TenantID {
		t.Fatal("original scope changed")
	}
	original := b
	b.ExpectedVersion++
	again, err := recovery.Bindings()
	if err != nil || again != original {
		t.Fatal("owned recovery projection mutated original custody")
	}
	caller := r.Caller.Clone()
	caller.Request.Action = "identity.phone.verify.recover"
	request := phone.VerificationRecoveryRequestSpec{TenantID: r.TenantID, UserID: r.UserID, Caller: caller, Flow: r.Flow, Recovery: recovery}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*phone.VerificationRecoveryRequestSpec){
		"tenant":  func(r *phone.VerificationRecoveryRequestSpec) { r.TenantID = "foreign" },
		"action":  func(r *phone.VerificationRecoveryRequestSpec) { r.Caller.Request.Action = "identity.phone.verify" },
		"missing": func(r *phone.VerificationRecoveryRequestSpec) { r.Recovery = phone.VerificationRecovery{} },
		"flow":    func(r *phone.VerificationRecoveryRequestSpec) { r.Flow = otp.SendFlow{} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.Caller = request.Caller.Clone()
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatal("invalid recovery admitted")
			}
			if _, err := phone.NewVerificationRecoveryRequest(candidate); err == nil {
				t.Fatal("constructor admitted invalid recovery")
			}
		})
	}
	b.Attempt.CommandID = b.SendCommandID
	if _, err := phone.NewVerificationRecovery(b); err == nil {
		t.Fatal("send substituted for consuming attempt")
	}
	if _, err := phone.NewVerificationRecovery(otp.CheckRecoveryBindings{}); err == nil {
		t.Fatal("empty original custody admitted")
	}
}

func TestPhoneWorkflowDiagnosticsAndSerializationRedactAllCustody(t *testing.T) {
	r := verificationRequest(t)
	recovery := phoneRecovery(t, r)
	caller := r.Caller.Clone()
	caller.Request.Action = "identity.phone.verify.recover"
	enrollmentHandle, err := phone.NewEnrollmentRequest(enrollmentRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	verificationHandle, err := phone.NewVerificationRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	recoveryHandle, err := phone.NewVerificationRecoveryRequest(phone.VerificationRecoveryRequestSpec{TenantID: r.TenantID, UserID: r.UserID, Caller: caller, Flow: r.Flow, Recovery: recovery})
	if err != nil {
		t.Fatal(err)
	}
	enrollmentResult, err := phone.NewEnrollmentResult(phone.EnrollmentResultSpec{Binding: phoneResultBinding(t, "identity.phone.send-verification"), Outcome: identity.CommitOutcomeCommitted, IdentifierID: "private-result-record"})
	if err != nil {
		t.Fatal(err)
	}
	verificationResult, err := phone.NewVerificationResult(phone.VerificationResultSpec{Binding: phoneResultBinding(t, "identity.phone.verify"), Outcome: identity.CommitOutcomeUnknown})
	if err != nil {
		t.Fatal(err)
	}
	values := []interface {
		fmt.Formatter
		json.Marshaler
		MarshalText() ([]byte, error)
		slog.LogValuer
	}{
		enrollmentHandle, verificationHandle, recovery, recoveryHandle,
		enrollmentResult, verificationResult,
	}
	for _, value := range values {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private workflow implicitly JSON serialized")
		}
		if _, err := value.MarshalText(); err == nil {
			t.Fatal("private workflow implicitly text serialized")
		}
		for _, text := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), fmt.Sprintf("%q", value), value.LogValue().String()} {
			if !strings.Contains(text, "redacted") {
				t.Fatal("missing diagnostic redaction")
			}
			for _, secret := range []string{"+12025550123", "123456", "original-session", "original-device", "private-identifier", string(r.SendCommandID), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"} {
				if strings.Contains(text, secret) {
					t.Fatal("workflow custody leaked")
				}
			}
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
		text := fmt.Sprintf(verb, struct{ private phone.VerificationRecovery }{recovery})
		bindings, err := recovery.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{string(bindings.SendCommandID), string(bindings.Attempt.CommandID), string(bindings.Attempt.Fingerprint)} {
			if strings.Contains(text, secret) {
				t.Fatal("nested diagnostic traversed original recovery custody")
			}
		}
	}
}

func TestPhoneRequestsDoNotLeakThroughPrivateEnclosingField(t *testing.T) {
	enrollment, err := phone.NewEnrollmentRequest(enrollmentRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	spec := verificationRequest(t)
	verification, err := phone.NewVerificationRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	caller := spec.Caller.Clone()
	caller.Request.Action = "identity.phone.verify.recover"
	recovery, err := phone.NewVerificationRecoveryRequest(phone.VerificationRecoveryRequestSpec{TenantID: spec.TenantID, UserID: spec.UserID, Caller: caller, Flow: spec.Flow, Recovery: phoneRecovery(t, spec)})
	if err != nil {
		t.Fatal(err)
	}
	for name, wrapped := range map[string]any{
		"enrollment":   struct{ private phone.EnrollmentRequest }{enrollment},
		"verification": struct{ private phone.VerificationRequest }{verification},
		"recovery": struct {
			private phone.VerificationRecoveryRequest
		}{recovery},
	} {
		t.Run(name, func(t *testing.T) {
			for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
				text := fmt.Sprintf(verb, wrapped)
				for _, secret := range []string{"+12025550123", "123456", "original-session", "original-device", "192.0.2.1", string(spec.SendCommandID), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"} {
					if strings.Contains(text, secret) {
						t.Errorf("%s nested diagnostic disclosed private request custody", verb)
						break
					}
				}
			}
		})
	}
}

func TestPhoneCallerPayloadIsBoundedBeforeConstruction(t *testing.T) {
	for name, mutate := range map[string]func(*authorization.DecisionContext){
		"single-group": func(c *authorization.DecisionContext) {
			c.Request.Subject.Groups = []authorization.SubjectID{authorization.SubjectID(strings.Repeat("x", 129))}
		},
		"single-string": func(c *authorization.DecisionContext) {
			c.Request.Attributes = authorization.Attributes{"large": authorization.StringValue(strings.Repeat("x", 4097))}
		},
		"single-set-entry": func(c *authorization.DecisionContext) {
			c.Request.Attributes = authorization.Attributes{"large": authorization.StringSetValue([]string{strings.Repeat("x", 4097)})}
		},
		"set-cardinality": func(c *authorization.DecisionContext) {
			values := make([]string, 65)
			for i := range values {
				values[i] = fmt.Sprintf("entry-%d", i)
			}
			c.Request.Attributes = authorization.Attributes{"large": authorization.StringSetValue(values)}
		},
		"aggregate-bytes": func(c *authorization.DecisionContext) {
			c.Request.Attributes = authorization.Attributes{}
			for i := 0; i < 17; i++ {
				c.Request.Attributes[authorization.AttributeName(fmt.Sprintf("item-%d", i))] = authorization.StringValue(strings.Repeat("x", 4096))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			enrollment := enrollmentRequest(t)
			mutate(&enrollment.Caller)
			if _, err := phone.NewEnrollmentRequest(enrollment); err == nil {
				t.Error("oversized caller copied into enrollment custody")
			}
			verification := verificationRequest(t)
			mutate(&verification.Caller)
			if _, err := phone.NewVerificationRequest(verification); err == nil {
				t.Error("oversized caller copied into verification custody")
			}
			caller := verification.Caller.Clone()
			caller.Request.Action = "identity.phone.verify.recover"
			if _, err := phone.NewVerificationRecoveryRequest(phone.VerificationRecoveryRequestSpec{TenantID: verification.TenantID, UserID: verification.UserID, Caller: caller, Flow: verification.Flow, Recovery: phoneRecovery(t, verification)}); err == nil {
				t.Error("oversized caller copied into recovery custody")
			}
		})
	}
}

func phoneResultBinding(t *testing.T, operation string) identity.CommandBinding {
	t.Helper()
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return identity.CommandBinding{CommandID: command, TenantID: "tenant", UserID: "user", ActorKind: authorization.SubjectUser, ActorID: "user", RecordID: "private-result-record", OperationID: operation, SchemaID: operation + ".native-v1", SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(command)}
}

func TestPhoneResultsDoNotLeakThroughPrivateEnclosingField(t *testing.T) {
	send := phoneResultBinding(t, "identity.phone.send-verification")
	verify := phoneResultBinding(t, "identity.phone.verify")
	enrollment, err := phone.NewEnrollmentResult(phone.EnrollmentResultSpec{Binding: send, Outcome: identity.CommitOutcomeCommitted, IdentifierID: identity.IdentifierID(send.RecordID)})
	if err != nil {
		t.Fatal(err)
	}
	verification, err := phone.NewVerificationResult(phone.VerificationResultSpec{Binding: verify, Outcome: identity.CommitOutcomeCommitted})
	if err != nil {
		t.Fatal(err)
	}
	for name, wrapped := range map[string]any{
		"enrollment":   struct{ private phone.EnrollmentResult }{enrollment},
		"verification": struct{ private phone.VerificationResult }{verification},
	} {
		t.Run(name, func(t *testing.T) {
			for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
				text := fmt.Sprintf(verb, wrapped)
				for _, secret := range []string{string(send.CommandID), string(verify.CommandID), send.RecordID} {
					if strings.Contains(text, secret) {
						t.Errorf("%s nested diagnostic disclosed private result correlation", verb)
						break
					}
				}
			}
		})
	}
}

func TestPhoneOpaqueRequestsCopyCallerCollectionsAndDenyZero(t *testing.T) {
	for _, r := range []interface{ Validate() error }{phone.EnrollmentRequest{}, phone.VerificationRequest{}, phone.VerificationRecoveryRequest{}} {
		if r.Validate() == nil {
			t.Fatal("zero request admitted")
		}
	}
	if _, err := (phone.EnrollmentRequest{}).Bindings(); err == nil {
		t.Fatal("zero enrollment projected")
	}
	if _, err := (phone.VerificationRequest{}).Bindings(); err == nil {
		t.Fatal("zero verification projected")
	}
	if _, err := (phone.VerificationRecoveryRequest{}).Bindings(); err == nil {
		t.Fatal("zero recovery request projected")
	}
	seed := func(c *authorization.DecisionContext) {
		c.Request.Subject.Groups = []authorization.SubjectID{"original-group"}
		c.Request.Attributes = authorization.Attributes{"original": authorization.StringValue("original")}
		c.Request.Subject.Attributes = authorization.Attributes{"original": authorization.StringValue("original")}
		c.Request.Resource.Attributes = authorization.Attributes{"original": authorization.StringValue("original")}
		c.Request.Environment.Attributes = authorization.Attributes{"original": authorization.StringValue("original")}
	}
	t.Run("enrollment", func(t *testing.T) {
		s := enrollmentRequest(t)
		seed(&s.Caller)
		r, err := phone.NewEnrollmentRequest(s)
		if err != nil {
			t.Fatal(err)
		}
		assertCallerCopies(t, &s.Caller, func() (authorization.DecisionContext, error) { b, e := r.Bindings(); return b.Caller, e })
	})
	t.Run("verification", func(t *testing.T) {
		s := verificationRequest(t)
		seed(&s.Caller)
		r, err := phone.NewVerificationRequest(s)
		if err != nil {
			t.Fatal(err)
		}
		assertCallerCopies(t, &s.Caller, func() (authorization.DecisionContext, error) { b, e := r.Bindings(); return b.Caller, e })
	})
	t.Run("recovery", func(t *testing.T) {
		v := verificationRequest(t)
		v.Caller.Request.Action = "identity.phone.verify.recover"
		s := phone.VerificationRecoveryRequestSpec{TenantID: v.TenantID, UserID: v.UserID, Caller: v.Caller, Flow: v.Flow, Recovery: phoneRecovery(t, v)}
		seed(&s.Caller)
		r, err := phone.NewVerificationRecoveryRequest(s)
		if err != nil {
			t.Fatal(err)
		}
		assertCallerCopies(t, &s.Caller, func() (authorization.DecisionContext, error) { b, e := r.Bindings(); return b.Caller, e })
	})
}

func assertCallerCopies(t *testing.T, source *authorization.DecisionContext, read func() (authorization.DecisionContext, error)) {
	t.Helper()
	mutate := func(c authorization.DecisionContext) {
		c.Request.Subject.Groups[0] = "changed"
		for _, m := range []authorization.Attributes{c.Request.Attributes, c.Request.Subject.Attributes, c.Request.Resource.Attributes, c.Request.Environment.Attributes} {
			m["original"] = authorization.StringValue("changed")
		}
	}
	check := func(c authorization.DecisionContext) {
		if c.Request.Subject.Groups[0] != "original-group" {
			t.Error("caller groups aliased original custody")
		}
		for _, m := range []authorization.Attributes{c.Request.Attributes, c.Request.Subject.Attributes, c.Request.Resource.Attributes, c.Request.Environment.Attributes} {
			v, _ := m["original"].String()
			if v != "original" {
				t.Error("caller attribute map aliased original custody")
			}
		}
	}
	mutate(*source)
	b, err := read()
	if err != nil {
		t.Fatal(err)
	}
	check(b)
	mutate(b)
	var wait sync.WaitGroup
	for range 4 {
		wait.Go(func() {
			b, err := read()
			if err != nil {
				t.Error(err)
				return
			}
			check(b)
			mutate(b)
		})
	}
	wait.Wait()
	b, err = read()
	if err != nil {
		t.Fatal(err)
	}
	check(b)
}

func TestPhoneCallerAcceptsBoundedScalarValuesWithoutDroppingFacts(t *testing.T) {
	s := enrollmentRequest(t)
	s.Caller.Request.Subject.Groups = []authorization.SubjectID{authorization.SubjectID(strings.Repeat("g", 128))}
	s.Caller.Request.Attributes = authorization.Attributes{"text": authorization.StringValue(strings.Repeat("s", 4096)), "set": authorization.StringSetValue([]string{"one", "two"}), "bool": authorization.BoolValue(true), "int": authorization.IntValue(1), "float": authorization.MustFloatValue(1.5), "time": authorization.TimeValue(time.Now()), "ip": authorization.IPValue(netip.MustParseAddr("192.0.2.1")), "null": authorization.NullValue()}
	r, err := phone.NewEnrollmentRequest(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range s.Caller.Request.Attributes {
		if !value.Equal(b.Caller.Request.Attributes[key]) {
			t.Fatal("bounded caller fact lost")
		}
	}
}

func phoneProjection(t *testing.T, b identity.CommandBinding) identity.IdentifierProjection {
	t.Helper()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	p, err := identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: b.TenantID, UserID: b.UserID, IdentifierID: identity.IdentifierID(b.RecordID), ObservedAt: now, Values: identity.IdentifierValuesIncluded, State: identity.IdentifierState{User: identity.User{ID: b.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}, AuthorityVersion: 1, Identifiers: []identity.Identifier{{ID: identity.IdentifierID(b.RecordID), UserID: b.UserID, Kind: identity.IdentifierPhone, CanonicalValue: "+12025550123", Verified: true, Version: 1}}, Verifications: []identity.Verification{{IdentifierID: identity.IdentifierID(b.RecordID), State: identity.VerificationVerified, VerifiedAt: now.Add(-time.Minute), Version: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPhoneResultConstructorsFenceNativeScopeDurabilityAndDisclosure(t *testing.T) {
	send := phone.EnrollmentResultSpec{Binding: phoneResultBinding(t, "identity.phone.send-verification"), Outcome: identity.CommitOutcomeCommitted, IdentifierID: "private-result-record"}
	enrolled, err := phone.NewEnrollmentResult(send)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enrolled.Bindings()
	if err != nil || got.Binding != send.Binding || got.IdentifierID != send.IdentifierID {
		t.Fatal("original enrollment metadata changed")
	}
	got.Binding.RecordID = "changed"
	again, err := enrolled.Bindings()
	if err != nil || again.Binding != send.Binding {
		t.Fatal("result projection mutated original")
	}
	for name, mutate := range map[string]func(*phone.EnrollmentResultSpec){"operation": func(s *phone.EnrollmentResultSpec) { s.Binding.OperationID = "identity.phone.verify" }, "record": func(s *phone.EnrollmentResultSpec) { s.IdentifierID = "foreign" }, "missing-id": func(s *phone.EnrollmentResultSpec) { s.IdentifierID = "" }, "outcome": func(s *phone.EnrollmentResultSpec) { s.Outcome = 0 }, "retry": func(s *phone.EnrollmentResultSpec) { s.RetryAfter = time.Second }, "self": func(s *phone.EnrollmentResultSpec) { s.Binding.ActorID = "foreign" }} {
		t.Run("enrollment/"+name, func(t *testing.T) {
			s := send
			mutate(&s)
			if _, err := phone.NewEnrollmentResult(s); err == nil {
				t.Fatal("invalid enrollment metadata admitted")
			}
		})
	}
	binding := phoneResultBinding(t, "identity.phone.verify")
	verified := phone.VerificationResultSpec{Binding: binding, Outcome: identity.CommitOutcomeCommitted, Identifier: phoneProjection(t, binding)}
	result, err := phone.NewVerificationResult(verified)
	if err != nil {
		t.Fatal(err)
	}
	out, err := result.Bindings()
	if err != nil || out.Binding != binding {
		t.Fatal("original verification metadata changed")
	}
	for name, mutate := range map[string]func(*phone.VerificationResultSpec){"replay-projection": func(s *phone.VerificationResultSpec) { s.Replayed = true }, "unknown-projection": func(s *phone.VerificationResultSpec) { s.Outcome = identity.CommitOutcomeUnknown }, "foreign-tenant": func(s *phone.VerificationResultSpec) { s.Binding.TenantID = "foreign" }, "foreign-user": func(s *phone.VerificationResultSpec) { s.Binding.UserID = "foreign"; s.Binding.ActorID = "foreign" }, "foreign-record": func(s *phone.VerificationResultSpec) { s.Binding.RecordID = "foreign" }, "negative-retry": func(s *phone.VerificationResultSpec) { s.RetryAfter = -time.Second }} {
		t.Run("verification/"+name, func(t *testing.T) {
			s := verified
			mutate(&s)
			if _, err := phone.NewVerificationResult(s); err == nil {
				t.Fatal("invalid verification disclosure admitted")
			}
		})
	}
	request := verificationRequest(t)
	recovery := phoneRecovery(t, request)
	original, err := recovery.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	history := phone.VerificationResultSpec{Binding: binding, Outcome: identity.CommitOutcomeUnknown, Recovery: recovery}
	history.Binding.CommandID = original.Attempt.CommandID
	if _, err := phone.NewVerificationResult(history); err != nil {
		t.Fatal("valid original recovery denied", err)
	}
	history.Binding.CommandID = binding.CommandID
	if _, err := phone.NewVerificationResult(history); err == nil {
		t.Fatal("foreign attempt recovery admitted")
	}
	history.Binding.CommandID = original.Attempt.CommandID
	history.Binding.TenantID = "foreign"
	if _, err := phone.NewVerificationResult(history); err == nil {
		t.Fatal("foreign tenant recovery admitted")
	}
	if _, err := (phone.EnrollmentResult{}).Bindings(); err == nil {
		t.Fatal("zero enrollment result projected")
	}
	if _, err := (phone.VerificationResult{}).Bindings(); err == nil {
		t.Fatal("zero verification result projected")
	}
}
