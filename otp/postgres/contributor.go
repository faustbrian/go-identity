package postgres

import (
	"context"
	"fmt"

	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// ContributorConfig is trusted composition configuration for native counted
// denial. Schema contains installed challenge/lockout storage. Codec is an
// immutable owned codec; GlobalAuthorityID and UserPolicyNamespace select the
// actual deployment and authorization owner, not request-selected namespaces.
// LockoutKey is dedicated and stable across code rotations. PreAuth and its
// retained cookie keys select installed session-owned original flow authority.
// Constructor copies keys and performs no IO. Do not mutate input concurrently.
type ContributorConfig struct {
	Schema, GlobalAuthorityID, UserPolicyNamespace string
	Codec                                          *AttemptCodec
	LockoutKey                                     [32]byte
	PreAuth                                        sessionpg.Config
	PreAuthCookieKeys                              map[uint32][]byte
}

// Format redacts all configuration and keys.
func (ContributorConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.ContributorConfig(redacted)"))
}

// MarshalJSON denies secret configuration export.
func (ContributorConfig) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies secret configuration export.
func (ContributorConfig) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Contributor implements the coordinator-owned wrong-code transaction for
// consuming pre-auth submissions. It owns no pool, transaction, retry, hook,
// goroutine or independent replay log. Enlist the exact returned pointer;
// instances are immutable and concurrent-safe, phase handles are serial-use.
//
// This development profile intentionally does not implement reservation or
// protected execution interfaces yet. Correct codes return Unchanged (rollback),
// never successful authentication. Authenticated-session and successful Check
// profiles remain unavailable until their full original custody/result paths
// exist. The complete consuming workflow remains under development.
type Contributor struct {
	schema, global, namespace string
	codec                     *AttemptCodec
	lockout                   lockoutProfile
	preauth                   *preAuthProfile
}

var _ kernel.OTPAttemptContributor = (*Contributor)(nil)

// NewContributor validates and copies native configuration without accessing
// services. Invalid/zero inputs return nil and redacted ErrInvalidConfiguration.
// Install the existing OTP and lockout migrations and exact lockout key binding
// before use; missing storage or mismatched deployment binding fails closed.
func NewContributor(c ContributorConfig) (*Contributor, error) {
	if !validSchema(c.Schema) || c.Codec == nil || c.Codec.crypto == nil ||
		(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: "validation"}).Validate() != nil ||
		(authoritypg.AuthorityScope{TenantID: "validation", SubjectID: "validation", PolicyNamespace: c.UserPolicyNamespace}).Validate() != nil {
		return nil, ErrInvalidConfiguration
	}
	l, err := newLockoutProfile(c.LockoutKey)
	if err != nil {
		return nil, err
	}
	p, err := newPreAuthProfile(c.PreAuth, c.PreAuthCookieKeys)
	if err != nil {
		return nil, err
	}
	return &Contributor{schema: c.Schema, global: c.GlobalAuthorityID, namespace: c.UserPolicyNamespace, codec: c.Codec, lockout: l, preauth: p}, nil
}

// Format redacts retained secret configuration, including nil receivers.
func (*Contributor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.Contributor(redacted)"))
}

// MarshalJSON denies retained key export.
func (*Contributor) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies retained key export.
func (*Contributor) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// Descriptor is the fixed pure identity expected by the kernel OTP protocol.
func (*Contributor) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}
}

// ValidateOTPAttemptCommand authenticates original command/code binding and
// frozen authority locally, without SQL or a challenge comparison. This profile
// requires consuming mode and complete original pre-auth plus actual cookie;
// legacy/ID-only/session/check profiles deny rather than borrow fresh authority.
func (p *Contributor) ValidateOTPAttemptCommand(command identity.Command, plan kernel.OTPAttemptPlan) error {
	_, _, err := p.original(command, plan)
	return err
}

func (p *Contributor) original(command identity.Command, plan kernel.OTPAttemptPlan) (otp.AttemptCommand, AttemptAuthority, error) {
	bad := func() (otp.AttemptCommand, AttemptAuthority, error) {
		return otp.AttemptCommand{}, AttemptAuthority{}, ErrInvalidCommand
	}
	if p == nil || p.codec == nil || p.preauth == nil || plan.Mode != kernel.OTPConsume {
		return bad()
	}
	spec, ok := command.Feature()
	if !ok {
		return bad()
	}
	authority, err := p.codec.restoreAuthority(spec)
	if err != nil || authority.Directory.Query.GlobalAuthorityID != p.global || spec.Binding.UserID != "" && authority.UserAuthorization.Scope.PolicyNamespace != p.namespace {
		return bad()
	}
	a, err := p.codec.restoreAttempt(command, plan)
	if err != nil {
		return bad()
	}
	ctx, stop := context.WithTimeout(context.Background(), p.codec.maximumDuration)
	defer stop()
	if _, err = p.codec.authenticatePreAuth(ctx, p.preauth, command, plan); err != nil {
		return bad()
	}
	return a, authority, nil
}

// RecordOTPAttemptDenial runs only inside the exact registered owner's live
// denial callback. Replay has already been resolved by the coordinator. Current
// primary authority and original flow/cookie precede ordered shared lockouts
// and challenge locking. One new wrong-code/expiry proposal is persisted with
// any exhaustion lockout; coordinator owns required audits, receipt and commit.
// Correct codes and unchanged/terminal/stale challenges return Unchanged and
// roll back all provisional SQL. No code is logged, stored or compared twice.
// Caller cancellation and bounded Work errors abort; no local retry occurs.
func (p *Contributor) RecordOTPAttemptDenial(ctx context.Context, w kernel.OTPAttemptWork) (kernel.OTPAttemptDisposition, error) {
	if ctx == nil || p == nil {
		return 0, ErrInvalidCommand
	}
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	command, err := w.NativeCommand(p)
	if err != nil {
		return 0, err
	}
	a, authority, err := p.original(command, b.Plan)
	if err != nil {
		return 0, err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, p, authority.Directory); err != nil {
		return 0, err
	}
	if b.Command.UserID != "" {
		expected := kernel.UserAuthorityAdmission{UserAuthorityVersion: authority.UserAuthorityVersion, IdentifierAuthorityVersion: authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: authority.CredentialAuthorityVersion}
		if err = w.RequireActiveUserAuthority(ctx, p, expected); err != nil {
			return 0, err
		}
		if authority.Credential != (identity.CredentialRef{}) {
			if _, err = w.RequireActiveCredential(ctx, p, kernel.CredentialAdmission{Credential: authority.Credential, UserAuthorityVersion: expected.UserAuthorityVersion, IdentifierAuthorityVersion: expected.IdentifierAuthorityVersion, CredentialAuthorityVersion: expected.CredentialAuthorityVersion}); err != nil {
				return 0, err
			}
		}
		if err = w.RequireActiveUserAuthorization(ctx, p, authority.UserAuthorization); err != nil {
			return 0, err
		}
	}
	flow, err := admitPreAuth(ctx, w, p.preauth, p.codec, command, b.Plan, nil)
	if err != nil {
		return 0, err
	}
	bindings, _ := a.Bindings()
	continuation, _ := bindings.Continuation.Bindings()
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	locked, _, err := p.lockout.loadLockouts(ctx, query, p.schema, continuation.Scope)
	if err != nil {
		return 0, err
	}
	row, err := p.codec.loadChallenge(ctx, query, p.schema, a, b.Plan.DigestKeyVersion)
	if err != nil {
		return 0, err
	}
	// Re-sample after the challenge lock: its wait cannot reuse earlier validity.
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return 0, err
	}
	// Locks preserve row identity and epochs, not time. Recheck the optional
	// credential through its existing owner after downstream waits. Its rows
	// are already share-locked by this transaction, so this acquires no new
	// earlier-order resource and cannot adopt a replacement credential.
	if authority.Credential != (identity.CredentialRef{}) {
		now, err = w.RequireActiveCredential(ctx, p, kernel.CredentialAdmission{Credential: authority.Credential, UserAuthorityVersion: authority.UserAuthorityVersion, IdentifierAuthorityVersion: authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: authority.CredentialAuthorityVersion})
		if err != nil {
			return 0, err
		}
	}
	original, err := flow.Bindings()
	if err != nil || flow.Check(now, original.Binding, original.Cookie) != nil {
		return 0, ErrInvalidCommand
	}
	d, err := p.codec.verifier.EvaluateAttempt(row.challenge, a, now)
	if err != nil {
		return 0, ErrInvalidCommand
	}
	snapshot, _ := row.challenge.Bindings()
	if d.Outcome == otp.AttemptReserved || d.Outcome == otp.AttemptChecked || d.Version == snapshot.Version {
		return kernel.OTPAttemptUnchanged, nil
	}
	if err = persistCount(ctx, w.Exec, row, d, now); err != nil {
		return 0, err
	}
	if d.LockoutAfter != 0 {
		if err = extendLockouts(ctx, w.Exec, locked, now, d.LockoutAfter); err != nil {
			return 0, err
		}
	}
	return kernel.OTPAttemptDenied, nil
}

// RecoverParticipant supplies no inferred noncommit from mutable counters.
// Dedicated denial recovery uses the coordinator's atomic terminal receipt;
// an unresolved journal remains unknown, never permission to compare again.
// This profile owns no consuming reservation or independently recoverable
// participant effect. Invalid/returned handles and cancellation deny.
func (p *Contributor) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || ctx == nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if _, err := w.Scope(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	return kernel.RecoveryUnknown, nil
}
