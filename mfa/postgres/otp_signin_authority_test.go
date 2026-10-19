package mfapostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func otpSigninFactorScope(t *testing.T, anonymous bool) (identity.FeatureCommandSpec, kernel.ContributorDescriptor, kernel.OTPAttemptPlan) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	b := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "recipient", ActorKind: authorization.SubjectServiceAccount, ActorID: "service", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "policy", PolicyVersion: 1, CorrelationID: string(id)}
	if anonymous {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		b.UserID, b.AnonymousFlowID = "", "original-flow"
	}
	return identity.FeatureCommandSpec{Binding: b, Operation: op}, kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}, kernel.OTPAttemptPlan{Mode: kernel.OTPConsume}
}

func TestOTPSigninFactorScopeRequiresExactConsumeProfileAndOriginalSubject(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		spec, descriptor, plan := otpSigninFactorScope(t, anonymous)
		if err := validateOTPSigninFactorScope(spec.Binding, spec, descriptor, plan, "recipient"); err != nil {
			t.Fatal("selected structural scope denied", err)
		}
		for _, mutation := range []string{"owner", "contract", "contract-version", "operation-owner", "operation", "schema", "schema-version", "record-policy", "subject-policy", "binding", "command", "tenant", "actor", "policy", "record", "user", "subject", "check", "mode"} {
			t.Run(mutation+map[bool]string{true: "-anonymous", false: "-user"}[anonymous], func(t *testing.T) {
				s, d, p, user := spec, descriptor, plan, identity.UserID("recipient")
				binding := s.Binding
				switch mutation {
				case "owner":
					d.Owner = "foreign/postgres"
				case "contract":
					d.ContractID = "identity.otp"
				case "contract-version":
					d.Version++
				case "operation-owner":
					s.Operation.Owner = "identity/mfa"
				case "operation":
					s.Operation.OperationID = "identity.otp.check"
					s.Binding.OperationID = s.Operation.OperationID
					binding = s.Binding
				case "schema":
					s.Operation.SchemaID = "identity-otp-check"
					s.Binding.SchemaID = s.Operation.SchemaID
					binding = s.Binding
				case "schema-version":
					s.Operation.SchemaVersion++
					s.Binding.SchemaVersion++
					binding = s.Binding
				case "record-policy":
					s.Operation.RecordRequirement = identity.FeatureRecordRequired
					s.Binding.RecordID = "record"
					binding = s.Binding
				case "subject-policy":
					s.Operation.SubjectRequirement = identity.FeatureSubjectRequirement(2)
				case "binding":
					binding.CorrelationID = "substituted"
				case "command":
					s.Binding.CommandID = "invalid"
					binding = s.Binding
				case "tenant":
					s.Binding.TenantID = ""
					binding = s.Binding
				case "actor":
					s.Binding.ActorKind = ""
					binding = s.Binding
				case "policy":
					s.Binding.PolicyVersion = 0
					binding = s.Binding
				case "record":
					s.Binding.RecordID = "record"
					binding = s.Binding
				case "user":
					user = "bad user"
				case "subject":
					if anonymous {
						s.Binding.UserID = user
					} else {
						user = "other-user"
					}
					binding = s.Binding
				case "check":
					p.Mode = kernel.OTPCheck
				case "mode":
					p.Mode = 0
				}
				if err := validateOTPSigninFactorScope(binding, s, d, p, user); err == nil {
					t.Fatal("substituted factor admission accepted")
				}
			})
		}
	}
}

func TestPhoneOTPSigninFactorsRequireExactNativeConsumingScope(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		spec, descriptor, plan := otpSigninFactorScope(t, anonymous)
		spec.Operation.Owner = "identity/phone"
		spec.Operation.OperationID, spec.Binding.OperationID = "identity.phone.signin", "identity.phone.signin"
		spec.Operation.SchemaID, spec.Binding.SchemaID = "identity.phone.signin.native-v1", "identity.phone.signin.native-v1"
		if err := validateOTPSigninFactorScope(spec.Binding, spec, descriptor, plan, "recipient"); err != nil {
			t.Fatal("native phone OTP scope cannot fence original factor generation", err)
		}
		wrong := spec
		wrong.Operation.Owner = "identity/otp"
		if validateOTPSigninFactorScope(wrong.Binding, wrong, descriptor, plan, "recipient") == nil {
			t.Fatal("phone OTP factor guard accepted substituted workflow owner")
		}
		wrong = spec
		wrong.Operation.OperationID, wrong.Binding.OperationID = "identity.phone.password-signin", "identity.phone.password-signin"
		if validateOTPSigninFactorScope(wrong.Binding, wrong, descriptor, plan, "recipient") == nil {
			t.Fatal("phone OTP factor guard accepted password workflow")
		}
		plan.Mode = kernel.OTPCheck
		if validateOTPSigninFactorScope(spec.Binding, spec, descriptor, plan, "recipient") == nil {
			t.Fatal("phone OTP factor guard accepted nonconsuming check")
		}
	}
}

type otpSigninFactorOwner struct{}

func (*otpSigninFactorOwner) Descriptor() kernel.ContributorDescriptor {
	panic("invalid invocation must not call contributor")
}
func (*otpSigninFactorOwner) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, identity.ForbiddenError{}
}
func (*otpSigninFactorOwner) ValidateOTPAttemptCommand(identity.Command, kernel.OTPAttemptPlan) error {
	return identity.ForbiddenError{}
}
func (*otpSigninFactorOwner) RecordOTPAttemptDenial(context.Context, kernel.OTPAttemptWork) (kernel.OTPAttemptDisposition, error) {
	return 0, identity.ForbiddenError{}
}
func (*otpSigninFactorOwner) ReserveOTP(context.Context, kernel.OTPReservationWork) error {
	return identity.ForbiddenError{}
}
func (*otpSigninFactorOwner) RebindOTP(context.Context, kernel.OTPReservationWork) error {
	return identity.ForbiddenError{}
}

func TestOTPSigninFactorRequestRequiresOriginalVersionAndCancellation(t *testing.T) {
	if err := validateOTPSigninFactorRequest(context.Background(), "recipient", 1); err != nil {
		t.Fatal("positive original generation denied", err)
	}
	for _, request := range []struct {
		ctx     context.Context
		user    identity.UserID
		version uint64
	}{{nil, "recipient", 1}, {context.Background(), "recipient", 0}, {context.Background(), "", 1}, {context.Background(), "bad user", 1}} {
		if err := validateOTPSigninFactorRequest(request.ctx, request.user, request.version); err == nil {
			t.Fatal("invalid factor request admitted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateOTPSigninFactorRequest(cancelled, "recipient", 1); !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation lost", err)
	}
}

func TestOTPSigninFactorGuardsRejectMissingOpaqueInvocation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var typedNil *otpSigninFactorOwner
	for _, owner := range []kernel.OTPReservationContributor{nil, typedNil, &otpSigninFactorOwner{}} {
		guards := []func(context.Context, identity.UserID, uint64) error{
			func(ctx context.Context, user identity.UserID, version uint64) error {
				return RequireOTPSigninAttemptFactors(ctx, kernel.OTPAttemptWork{}, owner, user, version)
			},
			func(ctx context.Context, user identity.UserID, version uint64) error {
				return RequireOTPSigninReservationFactors(ctx, kernel.OTPReservationWork{}, owner, user, version)
			},
			func(ctx context.Context, user identity.UserID, version uint64) error {
				return RequireOTPSigninApplyFactors(ctx, kernel.OTPApplyWork{}, owner, user, version)
			},
			func(ctx context.Context, user identity.UserID, version uint64) error {
				return RequireOTPSigninFinalizeFactors(ctx, kernel.OTPFinalizeWork{}, owner, user, version)
			},
		}
		for _, guard := range guards {
			for _, ctx := range []context.Context{nil, context.Background(), cancelled} {
				for _, request := range []struct {
					user    identity.UserID
					version uint64
				}{{"recipient", 1}, {"recipient", 0}, {"bad user", 1}} {
					if err := guard(ctx, request.user, request.version); err == nil {
						t.Fatal("missing opaque invocation admitted")
					}
				}
			}
			if err := guard(cancelled, "recipient", 1); !errors.Is(err, context.Canceled) {
				t.Fatal("earlier cancellation lost", err)
			}
		}
	}
	for _, ctx := range []context.Context{nil, context.Background(), cancelled} {
		state, err := ReadOTPSigninFactors(ctx, nil, "tenant", "recipient", time.Second)
		if err == nil || state.Version() != 0 {
			t.Fatal("missing primary inferred known-empty factors")
		}
	}
}
