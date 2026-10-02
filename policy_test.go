package identity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func policyFixture(t *testing.T) (PolicySet, PolicyEvaluatorConfig, RiskPolicyInput, ClaimsPolicyInput, RetentionPolicyInput, RedactionPolicyInput) {
	t.Helper()
	f := newQueryFixture(t)
	set := PolicySet{
		Authorize: f.service.authorize,
		AssessRisk: func(context.Context, RiskPolicyInput) (RiskPolicyDecision, error) {
			return RiskPolicyDecision{Level: RiskLow, Action: RiskAllow, PolicyID: "identity-read", PolicyVersion: 1, Reasons: []PolicyReason{"permitted"}}, nil
		},
		MapClaims: func(_ context.Context, in ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
			return ClaimsPolicyDecision{Claims: in.Claims, PolicyID: "identity-read", PolicyVersion: 1, Reason: "permitted"}, nil
		},
		DecideRetention: func(context.Context, RetentionPolicyInput) (RetentionPolicyDecision, error) {
			return RetentionPolicyDecision{Disposition: RetentionAllow, PolicyID: "identity-read", PolicyVersion: 1, Reasons: []PolicyReason{"permitted"}}, nil
		},
		Redact: func(_ context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
			return RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: "identity-read", PolicyVersion: 1, Reason: "permitted"}, nil
		},
	}
	config := PolicyEvaluatorConfig{PolicyID: "identity-read", PolicyVersion: 1, Reasons: []PolicyReason{"permitted", "hold"}, MaximumDuration: time.Second}
	risk := RiskPolicyInput{TenantID: "tenant-a", ActorID: "actor-a", SubjectID: "user-a", OperationID: "identity.user.create", PolicyVersion: 1, Signals: []RiskSignal{{Name: "velocity", Value: AttributeScalar{Kind: AttributeInt64, Int64: 0}, ObservedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}}}
	claims := ClaimsPolicyInput{TenantID: "tenant-a", ActorID: "actor-a", OperationID: "identity.account.link", PolicyVersion: 1, Issuer: "https://issuer.example", Subject: "provider-user", Claims: []TypedClaim{{Name: "email_verified", Value: AttributeScalar{Kind: AttributeBool, Bool: false}, Sensitivity: SensitivityPublic}}}
	retention := RetentionPolicyInput{TenantID: "tenant-a", ActorID: "actor-a", SubjectID: "user-a", OperationID: "identity.user.anonymize", PolicyVersion: 1, Resource: RetentionResource{Kind: "identity.user", ID: "user-a"}, Action: RetentionAnonymize, RequestedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}
	redact := RedactionPolicyInput{TenantID: "tenant-a", ViewerID: "actor-a", Resource: RedactionResource{Kind: "identity.user", ID: "user-a"}, Fields: []FieldName{{"id"}, {"status"}}, OperationID: "identity.user.get", PolicyVersion: 1}
	return set, config, risk, claims, retention, redact
}

func TestPolicyEvaluatorFreezesCompositionAndBindsDeadline(t *testing.T) {
	set, cfg, risk, claims, retention, redact := policyFixture(t)
	original := set.AssessRisk
	set.AssessRisk = func(ctx context.Context, in RiskPolicyInput) (RiskPolicyDecision, error) {
		deadline, ok := ctx.Deadline()
		if !ok || !in.Deadline.Equal(deadline) || in.PolicyVersion != 1 {
			t.Fatal("missing exact bounded policy binding")
		}
		in.Signals[0].Name = "changed"
		return original(ctx, in)
	}
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Reasons[0] = "mutated"
	set.AssessRisk = nil
	d, err := e.AssessRisk(context.Background(), risk)
	if err != nil || d.Action != RiskAllow || risk.Signals[0].Name != "velocity" {
		t.Fatalf("risk = %v %v", d.Action, err)
	}
	c, err := e.MapClaims(context.Background(), claims)
	if err != nil || len(c.Claims) != 1 || c.Claims[0].Value.Bool {
		t.Fatal("false mapped claim lost")
	}
	r, err := e.DecideRetention(context.Background(), retention)
	if err != nil || r.Disposition != RetentionAllow {
		t.Fatal("explicit no legal hold was rejected")
	}
	p, err := e.Redact(context.Background(), redact)
	if err != nil || len(p.VisibleFields) != 2 {
		t.Fatal("valid projection denied")
	}
}

func TestPolicyEvaluatorRejectsMalformedOrFailedRiskWithoutFallback(t *testing.T) {
	for _, mode := range []string{"zero", "stale", "reason", "enum", "error", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			set, cfg, in, _, _, _ := policyFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			set.AssessRisk = func(context.Context, RiskPolicyInput) (RiskPolicyDecision, error) {
				d := RiskPolicyDecision{Level: RiskLow, Action: RiskAllow, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reasons: []PolicyReason{"permitted"}}
				switch mode {
				case "zero":
					return RiskPolicyDecision{}, nil
				case "stale":
					d.PolicyVersion = 2
				case "reason":
					d.Reasons = []PolicyReason{"unknown"}
				case "enum":
					d.Action = "invented"
				case "error":
					return d, errors.New("private-provider-detail")
				case "panic":
					panic("private-provider-detail")
				case "cancel":
					cancel()
				}
				return d, nil
			}
			e, err := NewPolicyEvaluator(set, cfg)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.AssessRisk(ctx, in)
			if err == nil || !reflect.DeepEqual(d, RiskPolicyDecision{}) || strings.Contains(err.Error(), "private") {
				t.Fatal("failed policy returned usable authority or leaked details")
			}
		})
	}
}

func TestPolicyEvaluatorLegalHoldAndRedactionPartitionFailClosed(t *testing.T) {
	set, cfg, _, _, in, projection := policyFixture(t)
	in.LegalHold = true
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.DecideRetention(context.Background(), in)
	if err == nil || !reflect.DeepEqual(d, RetentionPolicyDecision{}) {
		t.Fatal("legal hold allowed anonymization")
	}
	set.Redact = func(context.Context, RedactionPolicyInput) (RedactionPolicyDecision, error) {
		return RedactionPolicyDecision{VisibleFields: []FieldName{{"id"}}, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reason: "permitted"}, nil
	}
	e, err = NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.Redact(context.Background(), projection)
	if err == nil || !reflect.DeepEqual(p, RedactionPolicyDecision{}) {
		t.Fatal("incomplete projection partition was accepted")
	}
}

func TestPolicyEvaluatorEveryCallbackFailsClosedAndPreservesCancellation(t *testing.T) {
	for _, kind := range []string{"claims", "retention", "redaction"} {
		for _, mode := range []string{"error", "panic", "cancel", "deadline"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				set, cfg, _, claims, retention, redact := policyFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fail := func(ctx context.Context) error {
					switch mode {
					case "panic":
						panic("private-provider-detail")
					case "cancel":
						cancel()
					case "deadline":
						<-ctx.Done()
					}
					return errors.New("private-provider-detail")
				}
				if mode == "deadline" {
					cfg.MaximumDuration = time.Millisecond
				}
				switch kind {
				case "claims":
					set.MapClaims = func(ctx context.Context, in ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
						return ClaimsPolicyDecision{Claims: in.Claims, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reason: "permitted"}, fail(ctx)
					}
				case "retention":
					set.DecideRetention = func(ctx context.Context, _ RetentionPolicyInput) (RetentionPolicyDecision, error) {
						return RetentionPolicyDecision{Disposition: RetentionAllow, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reasons: []PolicyReason{"permitted"}}, fail(ctx)
					}
				case "redaction":
					set.Redact = func(ctx context.Context, in RedactionPolicyInput) (RedactionPolicyDecision, error) {
						return RedactionPolicyDecision{VisibleFields: in.Fields, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reason: "permitted"}, fail(ctx)
					}
				}
				e, err := NewPolicyEvaluator(set, cfg)
				if err != nil {
					t.Fatal(err)
				}
				var zero bool
				switch kind {
				case "claims":
					var d ClaimsPolicyDecision
					d, err = e.MapClaims(ctx, claims)
					zero = reflect.DeepEqual(d, ClaimsPolicyDecision{})
				case "retention":
					var d RetentionPolicyDecision
					d, err = e.DecideRetention(ctx, retention)
					zero = reflect.DeepEqual(d, RetentionPolicyDecision{})
				case "redaction":
					var d RedactionPolicyDecision
					d, err = e.Redact(ctx, redact)
					zero = reflect.DeepEqual(d, RedactionPolicyDecision{})
				}
				if !zero || err == nil || strings.Contains(err.Error(), "private") {
					t.Fatal("callback failure leaked partial decision or diagnostics")
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation classification lost")
				}
				if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("deadline classification lost")
				}
			})
		}
	}
}

func TestPolicyEvaluatorClaimsAndReasonOutputsArePrivateCopies(t *testing.T) {
	set, cfg, risk, claims, _, _ := policyFixture(t)
	shared := []TypedClaim{{Name: "count", Value: AttributeScalar{Kind: AttributeInt64, Int64: 9223372036854775807}, Sensitivity: SensitivityPublic}}
	reasons := []PolicyReason{"permitted"}
	set.MapClaims = func(_ context.Context, in ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
		in.Claims[0].Name = "mutated"
		return ClaimsPolicyDecision{Claims: shared, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reason: "permitted"}, nil
	}
	set.AssessRisk = func(context.Context, RiskPolicyInput) (RiskPolicyDecision, error) {
		return RiskPolicyDecision{Level: RiskHigh, Action: RiskStepUp, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reasons: reasons}, nil
	}
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.MapClaims(context.Background(), claims)
	if err != nil || d.Claims[0].Value.Int64 != 9223372036854775807 || claims.Claims[0].Name != "email_verified" {
		t.Fatal("lossless/copy boundary failed")
	}
	shared[0].Name = "later"
	if d.Claims[0].Name != "count" {
		t.Fatal("returned claims aliased callback memory")
	}
	r, err := e.AssessRisk(context.Background(), risk)
	if err != nil || r.Action != RiskStepUp {
		t.Fatal("step-up decision lost")
	}
	reasons[0] = "later"
	if r.Reasons[0] != "permitted" {
		t.Fatal("returned reason aliases callback memory")
	}
}

func TestPolicyEvaluatorRejectsInvalidInputBeforeAnyCallback(t *testing.T) {
	for _, mode := range []string{"tenant", "actor", "operation", "version", "signals-nil", "signals-count", "signal-size", "signal-time", "signal-duplicate", "signal-kind"} {
		t.Run(mode, func(t *testing.T) {
			set, cfg, in, _, _, _ := policyFixture(t)
			called := false
			set.AssessRisk = func(context.Context, RiskPolicyInput) (RiskPolicyDecision, error) {
				called = true
				return RiskPolicyDecision{}, nil
			}
			switch mode {
			case "tenant":
				in.TenantID = ""
			case "actor":
				in.ActorID = ""
			case "operation":
				in.OperationID = ""
			case "version":
				in.PolicyVersion = 2
			case "signals-nil":
				in.Signals = nil
			case "signals-count":
				in.Signals = make([]RiskSignal, 65)
			case "signal-size":
				in.Signals[0].Value = AttributeScalar{Kind: AttributeString, String: strings.Repeat("a", 513)}
			case "signal-time":
				in.Signals[0].ObservedAt = time.Time{}
			case "signal-duplicate":
				in.Signals = append(in.Signals, in.Signals[0])
			case "signal-kind":
				in.Signals[0].Value.Kind = AttributeStringList
			}
			e, err := NewPolicyEvaluator(set, cfg)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.AssessRisk(context.Background(), in)
			var invalid InvalidInputError
			if !errors.As(err, &invalid) || called || !reflect.DeepEqual(d, RiskPolicyDecision{}) {
				t.Fatal("invalid input reached policy")
			}
		})
	}
	for _, mode := range []string{"issuer", "userinfo", "query", "subject", "claims-nil", "count", "duplicate", "secret", "mixed", "oversized"} {
		t.Run("claims/"+mode, func(t *testing.T) {
			set, cfg, _, in, _, _ := policyFixture(t)
			called := false
			set.MapClaims = func(context.Context, ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
				called = true
				return ClaimsPolicyDecision{}, nil
			}
			switch mode {
			case "issuer":
				in.Issuer = "not-a-uri"
			case "userinfo":
				in.Issuer = "https://user:password@issuer.example"
			case "query":
				in.Issuer = "https://issuer.example?secret=value"
			case "subject":
				in.Subject = ""
			case "claims-nil":
				in.Claims = nil
			case "count":
				in.Claims = make([]TypedClaim, 129)
			case "duplicate":
				in.Claims = append(in.Claims, in.Claims[0])
			case "secret":
				in.Claims[0].Sensitivity = SensitivitySecret
			case "mixed":
				in.Claims[0].Value.String = "inactive arm"
			case "oversized":
				in.Claims[0].Value = AttributeScalar{Kind: AttributeString, String: strings.Repeat("a", 4097)}
			}
			e, err := NewPolicyEvaluator(set, cfg)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.MapClaims(context.Background(), in)
			var invalid InvalidInputError
			if !errors.As(err, &invalid) || called || !reflect.DeepEqual(d, ClaimsPolicyDecision{}) {
				t.Fatal("invalid provider data reached mapping")
			}
		})
	}
}

func TestPolicyEvaluatorRejectsMissingMembersAndMutableInvalidConfiguration(t *testing.T) {
	for _, mode := range []string{"authorization", "risk", "claims", "retention", "redaction", "id", "version", "duration-zero", "duration-long", "reasons-nil", "reason-duplicate", "reason-size"} {
		t.Run(mode, func(t *testing.T) {
			set, cfg, _, _, _, _ := policyFixture(t)
			switch mode {
			case "authorization":
				set.Authorize = nil
			case "risk":
				set.AssessRisk = nil
			case "claims":
				set.MapClaims = nil
			case "retention":
				set.DecideRetention = nil
			case "redaction":
				set.Redact = nil
			case "id":
				cfg.PolicyID = ""
			case "version":
				cfg.PolicyVersion = 0
			case "duration-zero":
				cfg.MaximumDuration = 0
			case "duration-long":
				cfg.MaximumDuration = time.Hour
			case "reasons-nil":
				cfg.Reasons = nil
			case "reason-duplicate":
				cfg.Reasons = []PolicyReason{"permitted", "permitted"}
			case "reason-size":
				cfg.Reasons = []PolicyReason{PolicyReason(strings.Repeat("a", 65))}
			}
			e, err := NewPolicyEvaluator(set, cfg)
			if err == nil || e != nil {
				t.Fatal("invalid composition accepted")
			}
		})
	}
}

func TestPolicyEvaluatorRetainsEarlierDeadlineAndDeniesExplicitCancellation(t *testing.T) {
	set, cfg, in, _, _, _ := policyFixture(t)
	in.Deadline = time.Now().Add(-time.Second)
	set.AssessRisk = func(context.Context, RiskPolicyInput) (RiskPolicyDecision, error) {
		t.Fatal("expired input reached callback")
		return RiskPolicyDecision{}, nil
	}
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.AssessRisk(context.Background(), in)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("input deadline was renewed")
	}
	in.Deadline = time.Time{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = e.AssessRisk(ctx, in)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled context reached callback")
	}
	_, err = e.AssessRisk(nil, in)
	var invalid InvalidInputError
	if !errors.As(err, &invalid) {
		t.Fatal("nil context accepted")
	}
}

func TestPolicyEvaluatorRetentionClosedVariantsAndUTC(t *testing.T) {
	for _, mode := range []string{"hold", "defer", "past", "unknown", "hold-without-hold", "allow-with-time"} {
		t.Run(mode, func(t *testing.T) {
			set, cfg, _, _, in, _ := policyFixture(t)
			in.LegalHold = mode == "hold"
			set.DecideRetention = func(context.Context, RetentionPolicyInput) (RetentionPolicyDecision, error) {
				d := RetentionPolicyDecision{Disposition: RetentionAllow, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reasons: []PolicyReason{"permitted"}}
				switch mode {
				case "hold", "hold-without-hold":
					d.Disposition = RetentionBlockLegalHold
				case "defer":
					d.Disposition = RetentionRetainUntil
					d.RetainUntil = in.RequestedAt.Add(time.Hour).In(time.FixedZone("offset", 3600))
				case "past":
					d.Disposition = RetentionRetainUntil
					d.RetainUntil = in.RequestedAt
				case "unknown":
					d.Disposition = "unknown"
				case "allow-with-time":
					d.RetainUntil = in.RequestedAt
				}
				return d, nil
			}
			e, err := NewPolicyEvaluator(set, cfg)
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.DecideRetention(context.Background(), in)
			if mode == "hold" || mode == "defer" {
				if err != nil {
					t.Fatal(err)
				}
				if mode == "defer" && d.RetainUntil.Location() != time.UTC {
					t.Fatal("retention instant not UTC")
				}
			} else if err == nil || !reflect.DeepEqual(d, RetentionPolicyDecision{}) {
				t.Fatal("invalid retention allowed")
			}
		})
	}
}

func TestPolicyEvaluatorRedactionComposesExistingReadAndCreation(t *testing.T) {
	set, cfg, _, _, _, _ := policyFixture(t)
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := newQueryFixture(t)
	f.service.config.RedactionReasons = []PolicyReason{"permitted"}
	f.service.redact = e.Redact
	got, err := f.service.UserGet(context.Background(), f.request)
	if err != nil || got.User.ID != f.repo.user.ID {
		t.Fatal("validated redaction failed existing read composition")
	}
	create, _, request := creationFixture(t)
	create.policy.config.RedactionReasons = []PolicyReason{"permitted"}
	create.policy.redact = e.Redact
	result, err := create.UserCreate(context.Background(), request)
	if err != nil || result.CommitOutcome != CommitOutcomeCommitted || result.User.ID != request.UserID {
		t.Fatal("validated redaction failed creation composition")
	}
}

func TestPolicyEvaluatorRedactionValidatesAgainstOriginalNotMutatedCallbackInput(t *testing.T) {
	set, cfg, _, _, _, in := policyFixture(t)
	set.Redact = func(_ context.Context, p RedactionPolicyInput) (RedactionPolicyDecision, error) {
		p.Fields[0] = FieldName{"unrequested"}
		return RedactionPolicyDecision{VisibleFields: p.Fields, PolicyID: cfg.PolicyID, PolicyVersion: 1, Reason: "permitted"}, nil
	}
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.Redact(context.Background(), in)
	if err == nil || !reflect.DeepEqual(d, RedactionPolicyDecision{}) || in.Fields[0].Value != "id" {
		t.Fatal("callback changed requested field authority")
	}
}

func TestPolicyEvaluatorRejectsIssuerWithoutHostName(t *testing.T) {
	set, cfg, _, in, _, _ := policyFixture(t)
	in.Issuer = "https://:443"
	called := false
	set.MapClaims = func(context.Context, ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
		called = true
		return ClaimsPolicyDecision{}, nil
	}
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.MapClaims(context.Background(), in)
	var invalid InvalidInputError
	if called || !errors.As(err, &invalid) {
		t.Fatal("hostless issuer reached provider claim mapping")
	}
}

func TestPolicyEvaluatorRejectsEmptyIssuerFragmentBeforeCallback(t *testing.T) {
	set, cfg, _, in, _, _ := policyFixture(t)
	in.Issuer = "https://issuer.example#"
	called := false
	set.MapClaims = func(context.Context, ClaimsPolicyInput) (ClaimsPolicyDecision, error) {
		called = true
		return ClaimsPolicyDecision{}, nil
	}
	e, err := NewPolicyEvaluator(set, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.MapClaims(context.Background(), in)
	var invalid InvalidInputError
	if called || !errors.As(err, &invalid) {
		t.Fatal("empty issuer fragment reached provider claim mapping")
	}
}

func FuzzPolicyClaimAdmission(f *testing.F) {
	f.Add("https://issuer.example", "provider-user", "email_verified", "public-example")
	f.Add("https://:443", "provider-user", "claim", "")
	f.Add("https://issuer.example#", "provider-user", "claim", "")
	f.Add("https://issuer.example?query=value", "provider-user", "claim", "value")
	f.Add("https://issuer.example", "provider-user", "claim", "\xff")
	f.Fuzz(func(t *testing.T, issuer, subject, name, value string) {
		if len(issuer) > 5000 || len(subject) > 5000 || len(name) > 5000 || len(value) > 5000 {
			return
		}
		set, cfg, _, in, _, _ := policyFixture(t)
		in.Issuer = issuer
		in.Subject = subject
		in.Claims = []TypedClaim{{Name: name, Value: AttributeScalar{Kind: AttributeString, String: value}, Sensitivity: SensitivityPersonal}}
		e, err := NewPolicyEvaluator(set, cfg)
		if err != nil {
			t.Fatal("fixture configuration")
		}
		d, err := e.MapClaims(context.Background(), in)
		if err != nil {
			if !reflect.DeepEqual(d, ClaimsPolicyDecision{}) {
				t.Fatal("rejected admission retained mapping")
			}
			return
		}
		if len(d.Claims) != 1 || d.Claims[0].Name != name || d.Claims[0].Value.String != value || len(value) > 4096 || d.PolicyID != cfg.PolicyID || d.PolicyVersion != cfg.PolicyVersion {
			t.Fatal("accepted admission changed bounded claim or policy binding")
		}
	})
}
