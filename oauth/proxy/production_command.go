package oauthproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CallbackGeneration is a request-owned provider step. The command adapter may
// invoke it synchronously at most once, only after acknowledged reservation and
// a durable generation marker. Keep neither the function nor callback custody
// after the command returns. A reconciliation error is not a terminal denial.
type CallbackGeneration func(context.Context, OriginalCallback) (CallbackPrepared, error)

// ProductionCallbackCommandStore adapts a native transaction owner that already
// wraps reservation, external generation and settlement. Execute must return nil
// only on an acknowledged durable original outcome. Replays and recovery must
// not invoke generate again, and incomplete or ambiguous work must remain
// pending. The registered adapter owns expiry/current-authority fences, exact
// proof consumption and the required atomic audit. This port grants no local
// identity or session authority.
type ProductionCallbackCommandStore interface {
	ExecuteOAuthProxyForward(ctx context.Context, lookup CallbackLookup, generate CallbackGeneration) error
}

// CallbackPrepared carries native settlement input, not a committed handoff.
// An owner may borrow its bounded encrypted payload for the same original
// command, but must not return it to transport before acknowledged commit.
type CallbackPrepared struct {
	disposition CallbackDisposition
	destination string
	envelope    []byte
	flow        identity.PreAuthTransactionID
	issuedAt    time.Time
	until       time.Time
}

func (p CallbackPrepared) Disposition() CallbackDisposition { return p.disposition }
func (p CallbackPrepared) Envelope() []byte                 { return bytes.Clone(p.envelope) }

// ExpiresAt is the earliest transaction or signed-evidence expiry. A zero time
// means no handoff was prepared. Settlement and restore cannot extend it.
func (p CallbackPrepared) ExpiresAt() time.Time { return p.until }

func (CallbackPrepared) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthproxy.CallbackPrepared(redacted)"))
}

func (CallbackPrepared) MarshalJSON() ([]byte, error) { return nil, CallbackInvalid }
func (CallbackPrepared) MarshalText() ([]byte, error) { return nil, CallbackInvalid }

func (p CallbackPrepared) disclosableAt(now time.Time) bool {
	return p.disposition == CallbackForwarded && len(p.envelope) > 0 && !now.Before(p.issuedAt) && now.Before(p.until)
}

// NewProductionCommandCallback uses the same exact bound OAuth callback as
// NewProductionCallback but delegates its lifecycle to a durable command owner.
// Leave c.Store nil; selecting both owners is invalid. Construction does no I/O.
func NewProductionCommandCallback(c ProductionCallbackConfig, store ProductionCallbackCommandStore) (*ProductionCallback, error) {
	if c.Provider == nil {
		return nil, CallbackInvalid
	}
	return newProductionCommandCallback(c, c.Provider, store)
}

func newProductionCommandCallback(c ProductionCallbackConfig, provider callbackProviderExchange, store ProductionCallbackCommandStore) (*ProductionCallback, error) {
	if c.Store != nil || store == nil {
		return nil, CallbackInvalid
	}
	p, err := buildProductionCallback(c, provider)
	if err != nil {
		return nil, err
	}
	p.command = store
	return p, nil
}

type callbackGenerationCustody struct {
	mu                    sync.Mutex
	called, closed, reuse bool
	value                 CallbackPrepared
}

func (s *callbackGenerationCustody) claim() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.called || s.closed {
		s.reuse = true
		return false
	}
	s.called = true
	return true
}

func (s *callbackGenerationCustody) retain(value CallbackPrepared) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.reuse {
		return false
	}
	value.envelope = bytes.Clone(value.envelope)
	s.value = value
	return true
}

func (s *callbackGenerationCustody) close() (CallbackPrepared, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	value := s.value
	s.value = CallbackPrepared{}
	return value, s.reuse
}

func (p *ProductionCallback) executeCommand(ctx context.Context, lookup CallbackLookup, input identity.OAuthCallbackInput) (CallbackResult, error) {
	command, cancel := context.WithTimeout(ctx, p.profile.Timeout+2*storageBudget)
	defer cancel()
	var custody callbackGenerationCustody
	defer func() {
		prepared, _ := custody.close()
		clear(prepared.envelope)
	}()
	generate := func(work context.Context, original OriginalCallback) (CallbackPrepared, error) {
		if !custody.claim() {
			return CallbackPrepared{}, CallbackReconcile
		}
		defer original.Verifier.Destroy()
		if work == nil || work.Err() != nil || command.Err() != nil || original.ID == ([32]byte{}) {
			return CallbackPrepared{}, CallbackReconcile
		}
		// The store may detach its bounded settlement, but must not detach the
		// original provider exchange from the callback's cancellation/deadline.
		deadline, _ := command.Deadline()
		generation, stop := context.WithDeadline(work, deadline)
		defer stop()
		detach := context.AfterFunc(command, stop)
		defer detach()
		if command.Err() != nil || generation.Err() != nil {
			return CallbackPrepared{}, CallbackReconcile
		}
		value := p.prepareOriginal(generation, lookup, input, original)
		if command.Err() != nil || generation.Err() != nil {
			clear(value.envelope)
			value = CallbackPrepared{disposition: CallbackNeedsReconciliation}
		}
		if !custody.retain(value) {
			clear(value.envelope)
			return CallbackPrepared{}, CallbackReconcile
		}
		if value.disposition == CallbackNeedsReconciliation {
			return value, CallbackReconcile
		}
		return value, nil
	}
	err := p.command.ExecuteOAuthProxyForward(command, lookup, generate)
	prepared, reused := custody.close()
	defer clear(prepared.envelope)
	if reused || command.Err() != nil {
		return CallbackResult{}, CallbackReconcile
	}
	if errors.Is(err, ErrOriginalUnavailable) && prepared.disposition == 0 {
		return CallbackResult{}, CallbackDenied
	}
	if err != nil {
		return CallbackResult{}, CallbackReconcile
	}
	if prepared.disposition == CallbackRejected {
		return CallbackResult{}, CallbackDenied
	}
	if !prepared.disclosableAt(p.clock.Now()) || command.Err() != nil {
		return CallbackResult{}, CallbackReconcile
	}
	return CallbackResult{destination: prepared.destination, envelope: bytes.Clone(prepared.envelope), flow: prepared.flow, until: prepared.until}, nil
}
