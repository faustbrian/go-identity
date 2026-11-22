package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestAccountUnlinkTransactionRequiresRetainedOriginalPreparation(t *testing.T) {
	for _, mode := range []string{"complete", "missing-original", "missing-generated", "missing-ciphertext", "future-generation", "changed-generated"} {
		t.Run(mode, func(t *testing.T) {
			c, w, command, _ := preparedUnlinkInvocationFixture(t)
			r := w.state.execution.reservation
			switch mode {
			case "missing-original":
				r.request.source = nil
			case "missing-generated":
				r.executionRequest = nil
			case "missing-ciphertext":
				r.preparation.ciphertext = nil
			case "future-generation":
				r.preparation.generation = r.journal.generation + 1
			case "changed-generated":
				spec, counters, _ := command.AccountUnlinkCounterCommand()
				spec.SessionVersion++
				// Invalid opaque proof/intent custody must not become executable.
				changed, _ := identity.NewAccountUnlinkCommand(spec)
				changed, _ = identity.NewAccountUnlinkCounterCommand(changed, counters)
				r.executionRequest.source = &changed
			}
			if mode == "complete" {
				if !preparedAccountUnlinkReservation(r) {
					t.Fatal("actual retained original cannot select protected unlink")
				}
				return
			}
			if preparedAccountUnlinkReservation(r) {
				t.Fatal("incomplete or replaced original admitted to execution")
			}
			if work, err := c.Begin(t.Context(), Reservation{state: r}); err == nil || work.state != nil {
				t.Fatal("incomplete unlink preparation reached SQL")
			}
		})
	}
}
