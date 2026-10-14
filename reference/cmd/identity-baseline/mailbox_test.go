package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

func TestLocalMailboxRequiresParentAcknowledgementOnOpenAndRecovery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		calls := 0
		sender, err := openLocalMailboxWithSync(directory, func(root *os.Root) error {
			calls++
			if info, err := root.Lstat("mail"); err != nil || !info.IsDir() {
				t.Fatal("acknowledgement did not cover the capture parent")
			}
			return errors.New("synthetic directory acknowledgement failure")
		})
		if sender != nil {
			_ = sender.Close()
		}
		if err == nil || calls != 1 {
			t.Fatal("capture opened without durable parent acknowledgement")
		}
	}
	if sender, err := openLocalMailbox(directory); err != nil {
		t.Fatal("parent acknowledgement could not recover", err)
	} else {
		_ = sender.Close()
	}
}

func TestLocalMailboxDoesNotAcceptReplayUntilPublicationAcknowledged(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	sender, err := openLocalMailbox(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	attempt := delivery.Attempt{TenantID: baselineTenant, IntentID: "synthetic-intent-0001", Generation: 1, Channel: delivery.ChannelEmail, Recipient: "person@example.invalid", Body: "synthetic-message", ContentType: "text/plain", IdempotencyKey: "synthetic-provider-key-0001", ValidUntil: time.Now().UTC().Add(time.Minute)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sender.syncDirectory = func(*os.Root) error { return errors.New("synthetic directory acknowledgement failure") }
	for range 2 {
		result, err := sender.Send(ctx, attempt)
		if !errors.Is(err, delivery.ErrOutcomeUnknown) || result.State == delivery.StateAccepted {
			t.Fatal("unacknowledged capture publication accepted on first handoff or replay")
		}
		files, err := os.ReadDir(filepath.Join(directory, "mail"))
		if err != nil || len(files) != 1 {
			t.Fatal("unknown publication lost its exact recoverable content")
		}
	}
	sender.syncDirectory = syncRootDirectory
	result, err := sender.Send(ctx, attempt)
	if err != nil || result.State != delivery.StateAccepted {
		t.Fatal("exact captured handoff could not recover acknowledgement")
	}
}

func TestLocalMailboxAcceptsOneMessageWithoutClaimingProviderDelivery(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "baseline")
	if err := initializeCredentials(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	sender, err := openLocalMailbox(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	attempt := delivery.Attempt{TenantID: baselineTenant, IntentID: "synthetic-intent-0001", Generation: 1, Channel: delivery.ChannelEmail, Recipient: "person@example.invalid", Body: "synthetic-message", ContentType: "text/plain", IdempotencyKey: "synthetic-provider-key-0001", ValidUntil: time.Now().UTC().Add(time.Minute)}
	for range 2 {
		result, err := sender.Send(ctx, attempt)
		if err != nil || result.State != delivery.StateAccepted {
			t.Fatal("local handoff did not retain its accepted classification")
		}
	}
	files, err := os.ReadDir(filepath.Join(directory, "mail"))
	if err != nil || len(files) != 1 {
		t.Fatal("provider retry produced duplicate captured mail")
	}
	info, err := files[0].Info()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("captured mail is not private")
	}
	attempt.Body = "conflicting-message"
	if _, err := sender.Send(ctx, attempt); err == nil {
		t.Fatal("provider idempotency identity accepted changed content")
	}
	attempt.TenantID = "other"
	if _, err := sender.Send(ctx, attempt); err == nil {
		t.Fatal("foreign tenant captured")
	}
	attempt.TenantID, attempt.IdempotencyKey = baselineTenant, "synthetic-provider-key-0002"
	attempt.ValidUntil = time.Now().UTC().Add(-time.Second)
	if _, err := sender.Send(ctx, attempt); err == nil {
		t.Fatal("expired verification content captured")
	}
	attempt.ValidUntil = time.Now().UTC().Add(time.Minute)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := sender.Send(canceled, attempt); err == nil {
		t.Fatal("canceled handoff accepted")
	}
	files, _ = os.ReadDir(filepath.Join(directory, "mail"))
	if len(files) != 1 {
		t.Fatal("denied handoff leaked partial mail")
	}
}
