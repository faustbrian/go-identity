package passwordpostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
)

// PhoneEnrollmentDestination authenticates original input before shared delivery
// admission. A retained key reads its exact encrypted preparation, including
// after proof consumption; conflicting or corrupt custody never falls back.
// Missing keys permit only preliminary native reads with an unretained candidate
// ID. No mapping, challenge, debit, proof consumption, pending identifier or SMS
// is created. The sensitive result is rate input, not mutation authority.
// Borrowed owners are concurrency-safe; cancellation cannot extend the bound.
func (s *PhoneVerificationService) PhoneEnrollmentDestination(ctx context.Context, r phone.EnrollmentRequest) (out phone.Number, err error) {
	p := s.state()
	if ctx == nil || p == nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = phone.Number{}
		}
	}()
	request, err := r.Bindings()
	if err != nil {
		return out, err
	}
	intent, err := p.enrollmentRequestIntent(request)
	if err != nil {
		return out, err
	}
	phase := &phoneEnrollmentPhase{service: p, request: request}
	phase.coordinator, phase.registry, err = p.coordinator(phase, nil)
	if err != nil {
		return out, err
	}
	scope, caller, feature := p.enrollmentRequestScope(request, phase.Descriptor())
	binding, wire, found, err := phase.coordinator.ReadPreparedRequestKey(ctx, scope, request.IdempotencyKey, intent, caller, feature, phase)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	if found {
		if err = phase.restoreRequest(ctx, binding, wire); err != nil {
			return out, err
		}
	} else {
		id, e := identity.NewCommandID()
		if e != nil {
			return out, password.ErrPasswordWork
		}
		phase, err = p.prepareEnrollment(ctx, request, id)
		if err != nil {
			return out, err
		}
	}
	// restoreRequest binds the complete NumberRecord, including optional retained
	// national/display metadata. Do not reconstruct a lossy record from E.164.
	record, err := request.Number.Record()
	if err != nil || record.E164 != phase.intent.Change.CanonicalValue {
		return out, password.ErrPasswordWork
	}
	return p.policy.Restore(ctx, record)
}

// PhoneVerificationLifetime authenticates the original committed issuance and
// current pending-phone source before shared challenge admission. It returns
// the exact issued interval, never remaining validity or caller-selected TTL.
// It does not compare the submitted code, charge an attempt, recover an outcome,
// mutate a row or grant verification authority; Verify independently fences all
// current owners and atomic effects. Zero/error yields no metadata.
func (s *PhoneVerificationService) PhoneVerificationLifetime(ctx context.Context, r phone.VerificationRequest) (out time.Duration, err error) {
	p := s.state()
	if ctx == nil || p == nil {
		return 0, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = 0
		}
	}()
	request, err := r.Bindings()
	if err != nil {
		return 0, err
	}
	source, confirmation, err := p.restorePhoneSource(ctx, request.TenantID, request.UserID, request.Caller, request.Flow, request.SendCommandID, request.CSRFToken)
	if err != nil {
		return 0, err
	}
	if _, err = p.currentPhoneSource(ctx, request.Caller, source, true); err != nil {
		return 0, err
	}
	return confirmation.Lifetime()
}
