package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type otpAuthorityChecks struct {
	directory     func(context.Context, DirectoryAuthorityAdmission) error
	credential    func(context.Context, CredentialAdmission) (time.Time, error)
	authorization func(context.Context, UserAuthorizationAdmission) error
}

func TestOTPAuthorityIgnoredOpenCursorDenialPoisons(t *testing.T) {
	for _, phase := range []string{"attempt", "reservation", "apply", "finalize"} {
		for _, dimension := range []string{"directory", "credential"} {
			t.Run(phase+"/"+dimension, func(t *testing.T) {
				w, checks, _ := otpAuthorityFixture(t, context.Background(), phase, "")
				// The owner's outstanding cursor makes the bounded SQL gateway
				// reject another query before reaching storage. Closing it later
				// must not erase the failed admission invocation.
				w.state.rows = &WorkRows{}
				b := w.state.binding
				var err error
				if dimension == "directory" {
					err = checks.directory(context.Background(), DirectoryAuthorityAdmission{Query: DirectoryAuthorityQuery{GlobalAuthorityID: "global", TenantID: b.TenantID}, GlobalVersion: 1, TenantVersion: 1})
				} else {
					_, err = checks.credential(context.Background(), CredentialAdmission{Credential: identity.CredentialRef{ID: "ref", TenantID: b.TenantID, UserID: b.UserID, Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1})
				}
				w.state.rows = nil
				if err == nil || w.state.failed == nil || w.usable() == nil {
					t.Fatal("ignored cursor denial left Work usable after owner closed rows")
				}
			})
		}
	}
}

// This fixture exercises handle lifetime and reuse of owner checks. Production
// callback dispatch and transactional outcomes have separate integration suites.
func otpAuthorityFixture(t *testing.T, ctx context.Context, phase string, ownerMode string) (Work, otpAuthorityChecks, func()) {
	t.Helper()
	owner := &otpExecutionProbe{}
	c, command, plan := otpAttemptFixture(t, owner)
	spec, _ := command.Feature()
	_, _, admitted, err := c.prepareOTPReservation(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	ownedCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ownedCtx, cancel: cancel, binding: spec.Binding, generation: 1, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, journal: journalReservation{generation: 1}}}
	selected := owner
	if ownerMode == "foreign" {
		selected = &otpExecutionProbe{}
	}
	if ownerMode == "nil-owner" {
		selected = nil
	}
	r := otpReservationState{coordinator: c, work: w, plan: admitted, command: command, owner: owner, active: true}
	switch phase {
	case "attempt":
		h := OTPAttemptWork{state: &otpAttemptState{work: w, owner: owner, command: command, active: true}}
		return w, otpAuthorityChecks{
			func(ctx context.Context, e DirectoryAuthorityAdmission) error {
				return h.RequireActiveDirectoryAuthority(ctx, selected, e)
			},
			func(ctx context.Context, e CredentialAdmission) (time.Time, error) {
				return h.RequireActiveCredential(ctx, selected, e)
			},
			func(ctx context.Context, e UserAuthorizationAdmission) error {
				return h.RequireActiveUserAuthorization(ctx, selected, e)
			},
		}, func() { h.state.active = false }
	case "reservation":
		h := OTPReservationWork{state: &r}
		return w, otpAuthorityChecks{
			func(ctx context.Context, e DirectoryAuthorityAdmission) error {
				return h.RequireActiveDirectoryAuthority(ctx, selected, e)
			},
			func(ctx context.Context, e CredentialAdmission) (time.Time, error) {
				return h.RequireActiveCredential(ctx, selected, e)
			},
			func(ctx context.Context, e UserAuthorizationAdmission) error {
				return h.RequireActiveUserAuthorization(ctx, selected, e)
			},
		}, func() { h.state.active = false }
	case "apply":
		h := OTPApplyWork{state: &otpExecutionState{reservation: r, phase: otpCheck}}
		return w, otpAuthorityChecks{
			func(ctx context.Context, e DirectoryAuthorityAdmission) error {
				return h.RequireActiveDirectoryAuthority(ctx, selected, e)
			},
			func(ctx context.Context, e CredentialAdmission) (time.Time, error) {
				return h.RequireActiveCredential(ctx, selected, e)
			},
			func(ctx context.Context, e UserAuthorizationAdmission) error {
				return h.RequireActiveUserAuthorization(ctx, selected, e)
			},
		}, func() { h.state.phase = otpFinalize }
	case "finalize":
		h := OTPFinalizeWork{state: &otpExecutionState{reservation: r, phase: otpFinalize}}
		return w, otpAuthorityChecks{
			func(ctx context.Context, e DirectoryAuthorityAdmission) error {
				return h.RequireActiveDirectoryAuthority(ctx, selected, e)
			},
			func(ctx context.Context, e CredentialAdmission) (time.Time, error) {
				return h.RequireActiveCredential(ctx, selected, e)
			},
			func(ctx context.Context, e UserAuthorizationAdmission) error {
				return h.RequireActiveUserAuthorization(ctx, selected, e)
			},
		}, func() { h.state.phase = otpRelease }
	default:
		t.Fatal("unknown phase")
		return Work{}, otpAuthorityChecks{}, nil
	}
}

func TestOTPAuthorityLiveDenialsAndReturnedHandles(t *testing.T) {
	for _, phase := range []string{"attempt", "reservation", "apply", "finalize"} {
		for _, dimension := range []string{"directory", "credential", "authorization"} {
			for _, mode := range []string{"malformed", "foreign", "nil-owner", "nil-context", "canceled", "returned"} {
				t.Run(phase+"/"+dimension+"/"+mode, func(t *testing.T) {
					ctx := context.Background()
					w, checks, deactivate := otpAuthorityFixture(t, ctx, phase, mode)
					if mode == "nil-context" {
						ctx = nil
					}
					if mode == "canceled" {
						canceled, cancel := context.WithCancel(ctx)
						cancel()
						ctx = canceled
					}
					if mode == "returned" {
						deactivate()
					}
					var err error
					switch dimension {
					case "directory":
						err = checks.directory(ctx, DirectoryAuthorityAdmission{})
					case "credential":
						var now time.Time
						now, err = checks.credential(ctx, CredentialAdmission{})
						if !now.IsZero() {
							t.Fatal("denial disclosed clock")
						}
					case "authorization":
						err = checks.authorization(ctx, UserAuthorizationAdmission{})
					}
					if err == nil || w.state.sqlStarted {
						t.Fatal("invalid scope reached primary SQL")
					}
					if mode == "returned" {
						if w.state.failed != nil || w.usable() != nil {
							t.Fatal("returned handle poisoned a later phase")
						}
					} else if w.state.failed == nil || w.usable() == nil {
						t.Fatal("ignored live denial did not poison Work")
					}
					if mode == "canceled" {
						if !errors.Is(err, context.Canceled) {
							t.Fatalf("cancellation classification: %T", err)
						}
					}
				})
			}
		}
	}
}

func TestOTPAuthorityZeroHandles(t *testing.T) {
	attempt, reserve, apply, finalize := OTPAttemptWork{}, OTPReservationWork{}, OTPApplyWork{}, OTPFinalizeWork{}
	for _, check := range []func(context.Context, OTPAttemptContributor, DirectoryAuthorityAdmission) error{attempt.RequireActiveDirectoryAuthority} {
		if check(context.Background(), nil, DirectoryAuthorityAdmission{}) == nil {
			t.Fatal("zero attempt admitted authority")
		}
	}
	for _, check := range []func(context.Context, OTPReservationContributor, DirectoryAuthorityAdmission) error{reserve.RequireActiveDirectoryAuthority, apply.RequireActiveDirectoryAuthority, finalize.RequireActiveDirectoryAuthority} {
		if check(context.Background(), nil, DirectoryAuthorityAdmission{}) == nil {
			t.Fatal("zero phase admitted directory")
		}
	}
	for _, check := range []func(context.Context, OTPReservationContributor, CredentialAdmission) (time.Time, error){reserve.RequireActiveCredential, apply.RequireActiveCredential, finalize.RequireActiveCredential} {
		if now, err := check(context.Background(), nil, CredentialAdmission{}); err == nil || !now.IsZero() {
			t.Fatal("zero phase admitted credential")
		}
	}
	if now, err := attempt.RequireActiveCredential(context.Background(), nil, CredentialAdmission{}); err == nil || !now.IsZero() {
		t.Fatal("zero attempt admitted credential")
	}
	for _, check := range []func(context.Context, OTPReservationContributor, UserAuthorizationAdmission) error{reserve.RequireActiveUserAuthorization, apply.RequireActiveUserAuthorization, finalize.RequireActiveUserAuthorization} {
		if check(context.Background(), nil, UserAuthorizationAdmission{}) == nil {
			t.Fatal("zero phase admitted authorization")
		}
	}
	if attempt.RequireActiveUserAuthorization(context.Background(), nil, UserAuthorizationAdmission{}) == nil {
		t.Fatal("zero attempt admitted authorization")
	}
}
