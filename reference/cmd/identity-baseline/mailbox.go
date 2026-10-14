package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

// localMailbox is an explicitly selected loopback development destination,
// not a production sender or a domain queue. It receives rendered mail only;
// the native delivery owner retains scheduling, authority, expiry and retries.
// No Attempt is retained. Private message files are intentionally readable by
// the local consumer walkthrough and are never emitted to stdout or logs.
type localMailbox struct {
	root          *os.Root
	syncDirectory func(*os.Root) error
}

type mailboxMessage struct {
	Recipient  string    `json:"recipient"`
	Subject    string    `json:"subject"`
	Body       string    `json:"body"`
	ValidUntil time.Time `json:"validUntil"`
}

func openLocalMailbox(directory string) (*localMailbox, error) {
	return openLocalMailboxWithSync(directory, syncRootDirectory)
}

func syncRootDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
}

// The callback is a filesystem acknowledgement seam, not delivery authority.
func openLocalMailboxWithSync(directory string, syncDirectory func(*os.Root) error) (*localMailbox, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errCredentials
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errCredentials
	}
	defer root.Close()
	if err := root.Mkdir("mail", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errCredentials
	}
	info, err = root.Lstat("mail")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errCredentials
	}
	// A retry must acknowledge the parent even if a prior Mkdir succeeded but
	// its directory sync was unknown. Child sync alone cannot publish mail/.
	if syncDirectory(root) != nil {
		return nil, errCredentials
	}
	mail, err := root.OpenRoot("mail")
	if err != nil {
		return nil, errCredentials
	}
	return &localMailbox{root: mail, syncDirectory: syncDirectory}, nil
}

func (m *localMailbox) Close() error {
	if m == nil || m.root == nil {
		return nil
	}
	return m.root.Close()
}

func (m *localMailbox) Send(ctx context.Context, a delivery.Attempt) (result delivery.DeliveryResult, err error) {
	if m == nil || m.root == nil || ctx == nil || a.Validate() != nil || a.Channel != delivery.ChannelEmail || a.ContentType != "text/plain" || len(a.Body) > 4096 {
		return result, delivery.ErrInvalidInput
	}
	if string(a.TenantID) != baselineTenant {
		return result, delivery.ErrForbidden
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if !a.ValidUntil.After(time.Now()) {
		return result, delivery.ErrExpired
	}
	message, err := json.Marshal(mailboxMessage{Recipient: a.Recipient, Subject: a.Subject, Body: a.Body, ValidUntil: a.ValidUntil})
	if err != nil {
		return result, delivery.ErrInvalidInput
	}
	id := sha256.Sum256([]byte(a.IdempotencyKey))
	name := hex.EncodeToString(id[:]) + ".json"
	accepted := func() (delivery.DeliveryResult, error) {
		// Every acceptance, including an exact retry after unknown publication,
		// requires durable acknowledgement of the containing directory.
		if m.syncDirectory(m.root) != nil {
			return delivery.DeliveryResult{}, delivery.ErrOutcomeUnknown
		}
		if err := ctx.Err(); err != nil {
			return delivery.DeliveryResult{}, err
		}
		if !a.ValidUntil.After(time.Now()) {
			return delivery.DeliveryResult{}, delivery.ErrExpired
		}
		return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
	}
	if existing, err := m.read(name); err == nil {
		if !bytes.Equal(existing, message) {
			return result, delivery.ErrOutcomeUnknown
		}
		return accepted()
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, delivery.ErrUnavailable
	}
	directory, err := m.root.Open(".")
	if err != nil {
		return result, delivery.ErrUnavailable
	}
	entries, readErr := directory.ReadDir(1025)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) >= 1024 {
		return result, delivery.ErrUnavailable
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return result, delivery.ErrUnavailable
	}
	temporary := ".pending-" + hex.EncodeToString(random[:])
	file, err := m.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, delivery.ErrUnavailable
	}
	defer func() {
		if cleanupErr := m.root.Remove(temporary); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			result, err = delivery.DeliveryResult{}, delivery.ErrOutcomeUnknown
		}
	}()
	_, writeErr := file.Write(message)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr = file.Close()
	if writeErr != nil || closeErr != nil {
		return result, delivery.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// Link publishes only a complete synced file, never replaces existing mail.
	// Provider idempotency is content-checked; this is not a second work queue.
	if err := m.root.Link(temporary, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return result, delivery.ErrOutcomeUnknown
		}
		existing, readErr := m.read(name)
		if readErr != nil || !bytes.Equal(existing, message) {
			return result, delivery.ErrOutcomeUnknown
		}
	}
	return accepted()
}

func (m *localMailbox) read(name string) ([]byte, error) {
	before, err := m.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > 8192 || before.Size() < 1 {
		return nil, delivery.ErrUnavailable
	}
	file, err := m.root.Open(name)
	if err != nil {
		return nil, delivery.ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 {
		return nil, delivery.ErrUnavailable
	}
	content, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(content) > 8192 {
		return nil, delivery.ErrUnavailable
	}
	return content, nil
}
