package postgres

import (
	"errors"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
)

func TestCreateRejectsAbsentNativeOwnersWithoutIssuance(t *testing.T) {
	if s, err := NewService(nil, ServiceConfig{}); s != nil || !errors.Is(err, apikey.ErrInvalid) {
		t.Fatal("absent native owners accepted")
	}
	var s *Service
	out, err := s.Create(t.Context(), apikey.CreateRequest{})
	if !errors.Is(err, apikey.ErrInvalid) || out.DeliveryOutcome() != apikey.IssuanceUnspecified {
		t.Fatal("invalid invocation produced an issuance result")
	}
}

func TestRotateAndRevokeRejectAbsentNativeOwnersWithoutEffects(t *testing.T) {
	var s *Service
	out, err := s.Rotate(t.Context(), apikey.Rotation{})
	if !errors.Is(err, apikey.ErrInvalid) || out.DeliveryOutcome() != apikey.IssuanceUnspecified {
		t.Fatal("invalid rotation produced successor material")
	}
	receipt, err := s.Revoke(t.Context(), apikey.Revocation{})
	if !errors.Is(err, apikey.ErrInvalid) || receipt.Binding.CommandID != "" {
		t.Fatal("invalid revocation produced a command")
	}
}
