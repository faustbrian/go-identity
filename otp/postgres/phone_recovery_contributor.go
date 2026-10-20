package postgres

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// PhoneRecoveryPreparation selects the original encrypted factor and its
// existing native verifier. ValidUntil is the authenticated original recovery
// deadline, never a renewal. These inputs are not authorization; every live
// phase independently requires the current original primary and factor fences.
type PhoneRecoveryPreparation struct {
	Factor     mfapg.TOTPFactorSnapshot
	Verifier   *mfapg.PhoneRecoveryTOTPVerifier
	ValidUntil time.Time
}

// Format hides original factor/deadline and verifier custody for every verb.
func (PhoneRecoveryPreparation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneRecoveryPreparation(redacted)"))
}

// MarshalJSON rejects export of native preparation custody.
func (PhoneRecoveryPreparation) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects implicit export of native preparation custody.
func (PhoneRecoveryPreparation) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

type phoneRecoveryProfile struct {
	mu        sync.Mutex
	preparing bool
	started   bool
	current   *phoneRecoveryCustody
}

// NewPhoneRecoveryContributor selects only the exact joint phone-reset
// profile. Register this stable pointer before command generation, then call
// PreparePhoneRecovery with the final retained generated command outside SQL.
// One instance belongs to one invocation; it must not be shared by requests.
// Ordinary Contributor constructors do not admit this compound profile.
func NewPhoneRecoveryContributor(c ContributorConfig) (*Contributor, error) {
	p, err := newContributor(c, nil)
	if err != nil {
		return nil, err
	}
	p.phoneRecovery = &phoneRecoveryProfile{}
	return p, nil
}

func (p *Contributor) attemptSpec(command identity.Command) (identity.FeatureCommandSpec, bool) {
	if p != nil && p.phoneRecovery != nil {
		spec, _, _, ok := phoneRecoveryAttemptCustody(command)
		return spec, ok
	}
	return command.Feature()
}

// PreparePhoneRecovery authenticates the original encrypted OTP custody and
// actual browser bearer, then decrypts two independent one-use TOTP preparations
// before any Work/row locks. It accepts only final generated compound custody,
// not an input command or a caller-written factor verdict. Destroy the returned
// custody on every exit, including execution that never starts. Repreparation
// replaces only an unused preparation; a started invocation cannot be renewed.
func (p *Contributor) PreparePhoneRecovery(ctx context.Context, command identity.Command, plan kernel.OTPAttemptPlan, preparation PhoneRecoveryPreparation) (PhoneRecoveryCustody, error) {
	if ctx == nil || p == nil || p.phoneRecovery == nil || preparation.Verifier == nil || plan.Mode != kernel.OTPConsume {
		return PhoneRecoveryCustody{}, ErrInvalidCommand
	}
	spec, ok := command.PhonePasswordResetFeature()
	if !ok {
		return PhoneRecoveryCustody{}, ErrInvalidCommand
	}
	profile := p.phoneRecovery
	profile.mu.Lock()
	if profile.preparing || profile.started {
		profile.mu.Unlock()
		return PhoneRecoveryCustody{}, ErrInvalidCommand
	}
	profile.preparing = true
	old := profile.current
	profile.current = nil
	profile.mu.Unlock()
	if old != nil {
		(PhoneRecoveryCustody{state: old}).Destroy()
	}
	defer func() { profile.mu.Lock(); profile.preparing = false; profile.mu.Unlock() }()
	attempt, authority, err := p.original(command, plan)
	if err != nil {
		return PhoneRecoveryCustody{}, err
	}
	native, err := p.codec.restoreCustody(spec)
	if err != nil || native.authority == nil || !phoneRecoveryAttemptRecord(native.record) {
		return PhoneRecoveryCustody{}, ErrInvalidCommand
	}
	flow, err := p.authenticateFlowSpec(ctx, spec, plan, mustPhoneRecoveryCookie(command))
	if err != nil {
		return PhoneRecoveryCustody{}, err
	}
	counted, err := preparation.Verifier.Prepare(ctx, preparation.Factor, command, preparation.ValidUntil)
	if err != nil {
		return PhoneRecoveryCustody{}, err
	}
	completion, err := preparation.Verifier.Prepare(ctx, preparation.Factor, command, preparation.ValidUntil)
	if err != nil {
		counted.Destroy()
		return PhoneRecoveryCustody{}, err
	}
	if err := ctx.Err(); err != nil {
		counted.Destroy()
		completion.Destroy()
		return PhoneRecoveryCustody{}, err
	}
	s := &phoneRecoveryCustody{owner: p, command: command, spec: spec, plan: plan, attempt: attempt, authority: authority, native: native, flow: flow, preparation: preparation, counted: counted, completion: completion}
	profile.mu.Lock()
	profile.current = s
	profile.mu.Unlock()
	return PhoneRecoveryCustody{state: s}, nil
}

// The exact variant has already been checked; no generic bearer conversion is
// permitted at this representation boundary.
func mustPhoneRecoveryCookie(command identity.Command) authentication.BearerCredential {
	cookie, _ := command.PhonePasswordResetPreAuthCookie()
	return cookie
}

// PhoneRecoveryCustody owns two one-use plaintext preparations for one exact
// generated command and registered owner. Copies share terminal destruction.
// It is not an accepted factor, reservation or reusable authentication proof.
type PhoneRecoveryCustody struct{ state *phoneRecoveryCustody }

// Format hides command, encrypted metadata and one-use secret-owner custody.
func (PhoneRecoveryCustody) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneRecoveryCustody(redacted)"))
}

// MarshalJSON rejects export of invocation-local custody.
func (PhoneRecoveryCustody) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects implicit export of invocation-local custody.
func (PhoneRecoveryCustody) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

type phoneRecoveryCustody struct {
	owner               *Contributor
	command             identity.Command
	spec                identity.FeatureCommandSpec
	plan                kernel.OTPAttemptPlan
	attempt             otp.AttemptCommand
	authority           AttemptAuthority
	native              nativeCustody
	flow                nativeFlow
	preparation         PhoneRecoveryPreparation
	counted, completion mfapg.PreparedPhoneRecoveryTOTP
	recorded            *mfapg.PhoneRecoveryTOTPCompletion // actual successful CAS; owner.phoneRecovery.mu
	destroyed           bool                               // owner.phoneRecovery.mu
}

// Destroy clears both preparations on every alias. It is idempotent and waits
// for an in-flight bounded MFA comparison outside the invocation's mutex.
func (c PhoneRecoveryCustody) Destroy() {
	s := c.state
	if s == nil {
		return
	}
	p := s.owner.phoneRecovery
	p.mu.Lock()
	s.destroyed = true
	if p.current == s {
		p.current = nil
	}
	counted, completion := s.counted, s.completion
	s.command = identity.Command{}
	s.spec = identity.FeatureCommandSpec{}
	s.attempt = otp.AttemptCommand{}
	s.native = nativeCustody{}
	s.recorded = nil
	p.mu.Unlock()
	counted.Destroy()
	completion.Destroy()
}

// VerifyAndRecordTOTP performs a fresh actual TOTP verification/replay CAS in
// the parent feature's sole protected Work. Counted classification is never
// accepted as consuming proof. The parent must RequireRecorded in this same
// live Work before mutating the password; commit remains coordinator-owned.
func (c PhoneRecoveryCustody) VerifyAndRecordTOTP(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor) (mfapg.PhoneRecoveryTOTPCompletion, error) {
	if c.state == nil {
		return mfapg.PhoneRecoveryTOTPCompletion{}, ErrInvalidCommand
	}
	s, err := c.state.owner.phoneRecoveryCurrent(identity.Command{}, kernel.OTPAttemptPlan{}, nil)
	if err != nil || c.state != s.source {
		return mfapg.PhoneRecoveryTOTPCompletion{}, ErrInvalidCommand
	}
	recorded, err := mfapg.VerifyAndRecordPhoneRecoveryTOTP(ctx, w, owner, s.command, s.completion)
	if err != nil {
		return mfapg.PhoneRecoveryTOTPCompletion{}, err
	}
	profile := s.owner.phoneRecovery
	profile.mu.Lock()
	defer profile.mu.Unlock()
	if profile.current != s.source || s.source.destroyed || s.source.recorded != nil {
		return mfapg.PhoneRecoveryTOTPCompletion{}, ErrInvalidCommand
	}
	s.source.recorded = &recorded
	return recorded, nil
}

// A short-lock snapshot moves no authority and holds no mutex across Work IO or
// cryptography. Exact command identity is intentional: reconstituted aliases
// must go through the owner's final outside-lock preparation again.
type phoneRecoveryUse struct {
	phoneRecoveryCustody
	source *phoneRecoveryCustody
}

func (p *Contributor) phoneRecoveryCurrent(command identity.Command, plan kernel.OTPAttemptPlan, spec *identity.FeatureCommandSpec) (phoneRecoveryUse, error) {
	if p == nil || p.phoneRecovery == nil {
		return phoneRecoveryUse{}, ErrInvalidCommand
	}
	profile := p.phoneRecovery
	profile.mu.Lock()
	defer profile.mu.Unlock()
	s := profile.current
	if profile.preparing || s == nil || s.destroyed || command != (identity.Command{}) && command != s.command || plan != (kernel.OTPAttemptPlan{}) && plan != s.plan || spec != nil && !reflect.DeepEqual(*spec, s.spec) {
		return phoneRecoveryUse{}, ErrInvalidCommand
	}
	profile.started = true
	return phoneRecoveryUse{phoneRecoveryCustody: *s, source: s}, nil
}

func (p *Contributor) executionOriginal(command identity.Command, plan kernel.OTPAttemptPlan) (otp.AttemptCommand, AttemptAuthority, error) {
	if p.phoneRecovery == nil {
		return p.original(command, plan)
	}
	s, err := p.phoneRecoveryCurrent(command, plan, nil)
	if err != nil {
		return otp.AttemptCommand{}, AttemptAuthority{}, err
	}
	return s.attempt, s.authority, nil
}

func (p *Contributor) executionFlow(ctx context.Context, command identity.Command, plan kernel.OTPAttemptPlan) (nativeFlow, error) {
	if p.phoneRecovery == nil {
		return p.authenticateFlow(ctx, command, plan)
	}
	s, err := p.phoneRecoveryCurrent(command, plan, nil)
	if err != nil {
		return nativeFlow{}, err
	}
	return s.flow, nil
}

func (p *Contributor) executionRecord(command identity.Command, spec identity.FeatureCommandSpec, plan kernel.OTPAttemptPlan) (otp.CommandAttemptRecord, error) {
	if p.phoneRecovery == nil {
		return p.codec.restoreRecord(spec)
	}
	s, err := p.phoneRecoveryCurrent(command, plan, &spec)
	if err != nil {
		return otp.CommandAttemptRecord{}, err
	}
	return s.native.record, nil
}

func (p *Contributor) consumingOriginal(ctx context.Context, spec identity.FeatureCommandSpec, plan kernel.OTPAttemptPlan, cookie authentication.BearerCredential) (nativeCustody, nativeFlow, error) {
	if p.phoneRecovery == nil {
		c, err := p.codec.restoreCustody(spec)
		if err != nil {
			return nativeCustody{}, nativeFlow{}, err
		}
		flow, err := p.authenticateFlowSpec(ctx, spec, plan, cookie)
		return c, flow, err
	}
	s, err := p.phoneRecoveryCurrent(identity.Command{}, plan, &spec)
	if err != nil {
		return nativeCustody{}, nativeFlow{}, err
	}
	if _, err := authenticateOriginalPreAuth(ctx, p.preauth, s.flow.preauth, cookie); err != nil {
		return nativeCustody{}, nativeFlow{}, err
	}
	return s.native, s.flow, nil
}
