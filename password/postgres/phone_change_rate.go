package passwordpostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/session"
)

// PhoneChangeSession authenticates possession of the original named password
// session for transport subject and synchronizer mapping. It can read retained
// metadata after this flow invalidates the identifier epoch, but grants no live
// session, update, proof freshness or history-disclosure authority. The workflow
// independently fences current authority. Calls borrow existing owners, are
// concurrent-safe and cannot extend the configured or caller deadline.
func (s *PhoneChangeService) PhoneChangeSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	p := s.state()
	if ctx == nil || p == nil {
		return session.Session{}, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, p.config().MaximumDuration)
	defer stop()
	return p.common.possessedPhoneSession(ctx, tenant, flow)
}

// PhoneChangeDestination authenticates exact original sending input before
// shared delivery admission. Existing keys restore only authenticated retained
// custody, including after proof consumption; a conflict never falls back to a
// new request. Absent keys permit preliminary native reads under an unretained
// candidate ID only. This call creates no mapping, challenge, proof consumption,
// delivery or identifier transition. The sensitive result is rate input, not
// mutation permission. Errors and cancellation return no destination metadata.
func (s *PhoneChangeService) PhoneChangeDestination(ctx context.Context, r phone.ChangeRequest) (out phone.Number, err error) {
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
	intent, err := p.sendIntent(request)
	if err != nil {
		return out, err
	}
	phase := &phoneChangeSendPhase{service: p, request: request}
	phase.coordinator, phase.registry, err = p.coordinator(phase, nil)
	if err != nil {
		return out, err
	}
	scope, caller, feature := p.sendScope(request, phase.Descriptor())
	binding, wire, found, err := phase.coordinator.ReadPreparedRequestKey(ctx, scope, request.Enrollment.IdempotencyKey, intent, caller, feature, phase)
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
		phase, err = p.prepareSend(ctx, request, id)
		if err != nil {
			return out, err
		}
	}
	record, err := request.Enrollment.Number.Record()
	if err != nil || record.E164 != phase.intent.Change.CanonicalValue {
		return out, password.ErrPasswordWork
	}
	// Keep the whole selected NumberRecord, including retained display/metadata;
	// reconstructing from E.164 would silently change original keyed intent.
	return p.common.policy.Restore(ctx, record)
}

// PhoneUpdateLifetime authenticates the original committed new-number issuance
// and possessed sending session for shared secret-rate admission. It returns
// the immutable issued interval, never remaining validity or a renewed deadline.
// It compares no code, charges no attempt and grants no live proof or mutation
// authority; Update repeats current admission and atomic consumption. Errors and
// cancellation return no lifetime. Borrowed owners are bounded/concurrent-safe.
func (s *PhoneChangeService) PhoneUpdateLifetime(ctx context.Context, r phone.UpdateRequest) (out time.Duration, err error) {
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
	_, confirmation, err := p.restoreChangeSource(ctx, request.TenantID, request.UserID, request.Caller, request.Flow, request.SendCommandID, request.CSRFToken)
	if err != nil {
		return 0, err
	}
	return confirmation.Lifetime()
}
