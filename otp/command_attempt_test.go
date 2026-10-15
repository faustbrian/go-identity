package otp_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func commandAttemptScope() (identity.CommandBinding, identity.FeatureOperation) {
	d := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "subject", ActorID: "service", ActorKind: authorization.SubjectServiceAccount, OperationID: d.OperationID, PolicyID: "policy", PolicyVersion: 1, SchemaID: d.SchemaID, SchemaVersion: 1, CorrelationID: "correlation", RecordID: "target"}
	return b, d
}

func TestCommandBoundAttemptIndependentFingerprint(t *testing.T) {
	b, d := commandAttemptScope()
	c := attemptContinuation(t)
	key := [32]byte{9}
	i, _ := otp.NewAttemptIssuer(7, key)
	code, _ := auth.NewOneTimeCode("123456")
	a, err := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 11, code)
	if err != nil {
		t.Fatal(err)
	}
	// Literal fixture framing is independent of the production structural encoder.
	structural := []byte("identity-otp-command-scope-v1\x00")
	for _, s := range []string{"AQEBAQEBAQEBAQEBAQEBAQ", "tenant", "subject", "", "service", string(authorization.SubjectServiceAccount), "identity.otp.signin", "policy", "identity-otp-signin", "correlation", "target", "identity/otp", "identity.otp.signin", "identity-otp-signin"} {
		structural = binary.BigEndian.AppendUint16(structural, uint16(len(s)))
		structural = append(structural, s...)
	}
	structural = binary.BigEndian.AppendUint64(structural, 1)
	structural = binary.BigEndian.AppendUint32(structural, 1)
	structural = append(structural, 0)
	structural = binary.BigEndian.AppendUint32(structural, 1)
	structural = append(structural, 2, 0)
	digest := sha256.Sum256(structural)
	scope := []byte("identity-otp-code-scope-v1\x00")
	for _, s := range []string{"tenant", "signin", "subject", "email", "user@example.test", "challenge", "target"} {
		scope = binary.BigEndian.AppendUint16(scope, uint16(len(s)))
		scope = append(scope, s...)
	}
	scope = binary.BigEndian.AppendUint64(scope, 3)
	scope = binary.BigEndian.AppendUint64(scope, 4)
	cb, _ := c.Bindings()
	scope = append(scope, cb.Scope.AuthorizationBinding[:]...)
	frame := []byte("identity-otp-command-attempt-fingerprint-v1\x00")
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(scope)))
	frame = append(frame, scope...)
	frame = append(frame, 2)
	frame = binary.BigEndian.AppendUint64(frame, 11)
	frame = binary.BigEndian.AppendUint32(frame, 7)
	frame = append(frame, digest[:]...)
	msg := []byte("authentication-one-time-code-digest-v1\x00")
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(frame)))
	msg = append(msg, frame...)
	msg = append(msg, 0, 6)
	msg = append(msg, "123456"...)
	h := hmac.New(sha256.New, key[:])
	h.Write(msg)
	got, _ := a.Bindings()
	if string(got.Fingerprint) != base64.RawURLEncoding.EncodeToString(h.Sum(nil)) {
		t.Fatal("complete keyed command fingerprint changed")
	}
	retry, err := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 11, code)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := retry.Bindings()
	if r.Fingerprint != got.Fingerprint || r.AttemptID == got.AttemptID {
		t.Fatal("stable binding or distinct logical submission lost")
	}
	legacy, _ := i.Prepare(context.Background(), c, otp.AttemptModeConsume, 11, code)
	l, _ := legacy.Bindings()
	if l.Fingerprint == got.Fingerprint || l.CommandID != "" {
		t.Fatal("legacy domain gained command authority")
	}
}

func TestCommandBoundAttemptSeparatesStructuralFields(t *testing.T) {
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	b, d := commandAttemptScope()
	c := attemptContinuation(t)
	a, _ := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 1, code)
	base, _ := a.Bindings()
	for name, change := range map[string]func(*identity.CommandBinding, *identity.FeatureOperation){
		"command": func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.CommandID = "AgICAgICAgICAgICAgICAg" },
		"actor":   func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.ActorID = "other" },
		"actor-kind": func(b *identity.CommandBinding, _ *identity.FeatureOperation) {
			b.ActorKind = authorization.SubjectAPIKey
		},
		"operation": func(b *identity.CommandBinding, d *identity.FeatureOperation) {
			b.OperationID = "identity.otp.check"
			d.OperationID = b.OperationID
		},
		"policy":         func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.PolicyID = "other" },
		"policy-version": func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.PolicyVersion++ },
		"schema": func(b *identity.CommandBinding, d *identity.FeatureOperation) {
			b.SchemaID = "other"
			d.SchemaID = b.SchemaID
		},
		"schema-version": func(b *identity.CommandBinding, d *identity.FeatureOperation) { b.SchemaVersion++; d.SchemaVersion++ },
		"correlation":    func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.CorrelationID = "other" },
		"owner":          func(_ *identity.CommandBinding, d *identity.FeatureOperation) { d.Owner = "identity/email" },
		"record-policy": func(b *identity.CommandBinding, d *identity.FeatureOperation) {
			b.RecordID = ""
			d.RecordRequirement = identity.FeatureRecordOmitted
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy, descriptor := b, d
			change(&copy, &descriptor)
			other, err := i.PrepareForCommand(context.Background(), copy, descriptor, c, otp.AttemptModeConsume, 1, code)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := other.Bindings()
			if got.Fingerprint == base.Fingerprint {
				t.Fatal("changed command collapsed")
			}
		})
	}
}

func TestCommandBoundAttemptRejectsInvalidAndForeignScope(t *testing.T) {
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	b, d := commandAttemptScope()
	c := attemptContinuation(t)
	for name, change := range map[string]func(*identity.CommandBinding, *identity.FeatureOperation){
		"zero-binding":    func(b *identity.CommandBinding, _ *identity.FeatureOperation) { *b = identity.CommandBinding{} },
		"zero-operation":  func(_ *identity.CommandBinding, d *identity.FeatureOperation) { *d = identity.FeatureOperation{} },
		"tenant":          func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.TenantID = "other" },
		"subject":         func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.UserID = "other" },
		"target":          func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.RecordID = "other" },
		"mixed-namespace": func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.AnonymousFlowID = "flow" },
		"link-mode":       func(b *identity.CommandBinding, _ *identity.FeatureOperation) { b.LinkMode = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			copy, descriptor := b, d
			change(&copy, &descriptor)
			got, err := i.PrepareForCommand(context.Background(), copy, descriptor, c, otp.AttemptModeConsume, 1, code)
			if !errors.Is(err, otp.ErrInvalidAttempt) {
				t.Fatal("foreign/invalid command accepted")
			}
			if _, _, err = got.CommandBinding(); !errors.Is(err, otp.ErrInvalidAttempt) {
				t.Fatal("failure retained command")
			}
		})
	}
	if _, err := i.PrepareForCommand(context.Background(), b, d, otp.Continuation{}, otp.AttemptModeConsume, 1, code); !errors.Is(err, otp.ErrInvalidAttempt) {
		t.Fatal("zero continuation accepted")
	}
	if _, err := i.PrepareForCommand(nil, b, d, c, otp.AttemptModeConsume, 1, code); !errors.Is(err, otp.ErrInvalidAttempt) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := i.PrepareForCommand(ctx, b, d, c, otp.AttemptModeConsume, 1, code); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}

func TestCommandBoundAttemptAnonymousNamespaceIsExplicit(t *testing.T) {
	b, d := commandAttemptScope()
	b.UserID, b.AnonymousFlowID = "", "flow"
	d.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	s := digestScopeSpec(t)
	s.SubjectID, s.AuthorizationBinding = "", [32]byte{}
	authz, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuthID()})
	c, err := otp.NewContinuation(s, authz, rememberPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	a, err := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := a.Bindings()
	b.AnonymousFlowID = "other-flow"
	other, err := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := other.Bindings()
	if got.Fingerprint == base.Fingerprint {
		t.Fatal("different anonymous flow collapsed")
	}
	b.UserID = "subject"
	if _, err := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 1, code); !errors.Is(err, otp.ErrInvalidAttempt) {
		t.Fatal("mixed anonymous/user namespace admitted")
	}
}

func TestCommandBoundAttemptFreezesCompleteSubmissionAndRecovery(t *testing.T) {
	b, d := commandAttemptScope()
	c := attemptContinuation(t)
	i, _ := otp.NewAttemptIssuer(1, [32]byte{2})
	code, _ := auth.NewOneTimeCode("123456")
	a, e := i.PrepareForCommand(context.Background(), b, d, c, otp.AttemptModeConsume, 1, code)
	if e != nil {
		t.Fatal(e)
	}
	got, op, e := a.CommandBinding()
	if e != nil || got != b || op != d {
		t.Fatal("command scope changed")
	}
	r, _ := a.Recovery()
	bindings, _ := a.Bindings()
	if r.CommandID != b.CommandID || bindings.CommandID != b.CommandID || r.AttemptID != bindings.AttemptID || r.Fingerprint != bindings.Fingerprint {
		t.Fatal("recovery lost command/attempt identity")
	}
	// The legacy API remains non-command preparation, not dispatch authority.
	unbound, _ := i.Prepare(context.Background(), c, otp.AttemptModeConsume, 1, code)
	if _, _, e := unbound.CommandBinding(); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("unbound attempt gained a command")
	}
	if _, _, e := (otp.AttemptCommand{}).CommandBinding(); !errors.Is(e, otp.ErrInvalidAttempt) {
		t.Fatal("zero command binding")
	}
	b.ActorID = "changed"
	d.Owner = "changed"
	again, againOp, _ := a.CommandBinding()
	if again.ActorID != "service" || againOp.Owner != "identity/otp" {
		t.Fatal("input mutation retained")
	}
}
