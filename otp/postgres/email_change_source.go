package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

var _ otp.EmailChangeRateSource = (*EmailChangeService)(nil)

// EmailChangeSendDestination authenticates possession and the original committed
// change under current request disclosure. It reads no mutable replacement
// mailbox and creates no issuance, debit, notification or renewed validity.
// Matching terminal Send retries therefore retain the original budget source.
func (s *EmailChangeService) EmailChangeSendDestination(ctx context.Context, r otp.EmailChangeRequest) (out otp.DestinationInput, err error) {
	if ctx == nil || s == nil || s.base == nil || r.Validate() != nil {
		return out, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.base.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = otp.DestinationInput{}
		}
	}()
	original, err := s.EmailChangeSession(ctx, r.TenantID, r.Flow)
	if err != nil {
		return out, err
	}
	b, err := original.Bindings()
	if err != nil || b.UserID != r.UserID {
		return out, identity.ForbiddenError{}
	}
	q := changeOriginQuery(r.TenantID, r.UserID, r.OriginCommandID, r.AddressID, "identity.otp.email-change-request")
	origin, err := s.source.ReadChangeOrigin(ctx, q, r.Caller)
	if err != nil {
		return out, err
	}
	if err := s.admitProfile(origin); err != nil {
		return out, err
	}
	if _, err := newEmailChangeSendProfile(s.base.sender.owner.store, origin); err != nil {
		return out, err
	}
	return otp.NewDestinationInput(origin.Spec.Payload.CanonicalAddress.Record().Value)
}

// EmailChangeChallenge reads authentic original Send/change custody and requires
// current executable session authority before returning private budget metadata.
// The native completion repeats its own transactional target/factor checks.
// No code is inspected, attempt prepared or SQL mutation performed here.
func (s *EmailChangeService) EmailChangeChallenge(ctx context.Context, r otp.EmailChangeConfirmRequest) (out otp.EmailChangeChallenge, err error) {
	if ctx == nil || s == nil || s.base == nil || r.Validate() != nil {
		return out, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.base.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = otp.EmailChangeChallenge{}
		}
	}()
	base, err := s.completion(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return out, err
	}
	if err := s.admitProfile(*base.change); err != nil {
		return out, err
	}
	original, custody, flow, err := s.base.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return out, err
	}
	f, _ := original.Feature()
	if err := base.source.requireCurrent(ctx, f.Binding, custody.authority, flow); err != nil {
		return out, err
	}
	p, err := newEmailChangeSendProfile(base.sender.owner.store, *base.change)
	if err != nil {
		return out, err
	}
	issued, err := custody.challenge.Bindings()
	if err != nil {
		return out, err
	}
	return otp.EmailChangeChallenge{UserID: r.UserID, Target: p.target, Lifetime: issued.ExpiresAt.Sub(issued.IssuedAt)}, nil
}
