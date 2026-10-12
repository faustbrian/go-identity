package magiclinkpostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/magiclink"
)

func TestPublicConsumptionRequiresOwnedComposition(t *testing.T) {
	if s, err := NewConsumeService(nil, ConsumeConfig{}); err == nil || s != nil {
		t.Fatal("zero request/session composition constructed")
	}
	var s *ConsumeService
	if _, err := s.Consume(context.Background(), magiclink.ConsumeRequest{}); err == nil {
		t.Fatal("zero native service consumed a grant")
	}
	if user, challenge, lifetime, err := s.ConsumeRateSource(context.Background(), magiclink.ConsumeRequest{}); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("absent rate authority exposed source")
	}
}
