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
	"strings"

	"github.com/faustbrian/go-audit"
)

const auditCustodyBatchBytes = 2*16384 + 3

// localAuditCustody retains the exact native audit records before the primary
// append may become uncertain. It creates no event IDs, permission, command
// journal or alternate acknowledgement: only the borrowed native sink decides
// primary persistence. This private local-only custody survives process restart.
// The semaphore protects bounded filesystem publication, never network IO.
type localAuditCustody struct {
	root          *os.Root
	primary       audit.Sink
	privacy       audit.Redactor
	available     chan struct{}
	syncDirectory func(*os.Root) error
}

func openLocalAuditCustody(directory string, primary audit.Sink) (*localAuditCustody, error) {
	if primary == nil {
		return nil, errLocalProfile
	}
	// Re-entry cannot trust a serialized "redaction applied" marker. Reapply
	// the selected identity.security.v1 allowlist with the native policy owner,
	// and below require that it leaves the original canonical bytes unchanged.
	privacy, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true, AllowedAttributes: []string{"identity.profile", "command.id", "retention.class", "provider.kind", "provider.profile", "provider.version", "provider.result", "aggregate.type", "aggregate.id", "aggregate.before_version", "aggregate.after_version", "scope.impersonation_grant_id"}})
	if err != nil {
		return nil, errLocalProfile
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errCredentials
	}
	parent, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errCredentials
	}
	defer parent.Close()
	if err := parent.Mkdir("audit-custody", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errCredentials
	}
	info, err = parent.Lstat("audit-custody")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || syncRootDirectory(parent) != nil {
		return nil, errCredentials
	}
	root, err := parent.OpenRoot("audit-custody")
	if err != nil {
		return nil, errCredentials
	}
	return &localAuditCustody{root: root, primary: primary, privacy: privacy, available: make(chan struct{}, 1), syncDirectory: syncRootDirectory}, nil
}

func (a *localAuditCustody) Close() error {
	if a == nil || a.root == nil {
		return nil
	}
	return a.root.Close()
}

func (a *localAuditCustody) Append(ctx context.Context, record audit.Record) (audit.AppendResult, error) {
	result, err := a.AppendBatch(ctx, []audit.Record{record})
	if err != nil {
		return audit.AppendResult{}, err
	}
	return result.Results[0], nil
}

func (a *localAuditCustody) AppendBatch(ctx context.Context, records []audit.Record) (audit.BatchResult, error) {
	if ctx == nil || a == nil || a.root == nil || a.primary == nil || len(records) < 1 || len(records) > 2 {
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, audit.ErrInvalidArgument)
	}
	wire := make([]json.RawMessage, len(records))
	for i, record := range records {
		raw, err := audit.CanonicalJSON(record)
		if err != nil || record.ID() == "" || !record.RedactionApplied() || len(raw) > 16384 {
			return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, audit.ErrInvalidArgument)
		}
		parsed, err := audit.ParseCanonicalJSON(raw, audit.DefaultLimits())
		if err != nil || parsed.ID() != record.ID() {
			return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, audit.ErrInvalidArgument)
		}
		wire[i] = raw
	}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) > auditCustodyBatchBytes {
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, audit.ErrBatchTooLarge)
	}
	name := auditCustodyName(raw)
	if err := a.retain(ctx, name, raw); err != nil {
		// No primary append has occurred, even if local publication is uncertain.
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendRejected, err)
	}
	result, err := a.primary.AppendBatch(ctx, records)
	if err != nil {
		return result, err
	}
	if !auditCustodyAcknowledged(result, records) {
		return audit.BatchResult{}, audit.NewAppendError(audit.AppendUnknown, audit.ErrSinkProtocol)
	}
	// Primary persistence is known; failed local cleanup cannot make those
	// records disappear. A remaining copy reconciles as a native duplicate.
	if err := a.root.Remove(name); err == nil {
		_ = a.syncDirectory(a.root)
	}
	return result, nil
}

func auditCustodyAcknowledged(result audit.BatchResult, records []audit.Record) bool {
	if len(result.Results) != len(records) {
		return false
	}
	for i, item := range result.Results {
		if item.RecordID != records[i].ID() || (item.Status != audit.AppendAccepted && item.Status != audit.AppendDuplicate) {
			return false
		}
	}
	return true
}

func auditCustodyName(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]) + ".json"
}

func (a *localAuditCustody) read(name string) ([]byte, error) {
	before, err := a.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() < 1 || before.Size() > auditCustodyBatchBytes {
		return nil, errCredentials
	}
	file, err := a.root.Open(name)
	if err != nil {
		return nil, errCredentials
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errCredentials
	}
	raw, err := io.ReadAll(io.LimitReader(file, auditCustodyBatchBytes+1))
	if err != nil || len(raw) > auditCustodyBatchBytes {
		return nil, errCredentials
	}
	return raw, nil
}

func (a *localAuditCustody) retain(ctx context.Context, name string, raw []byte) error {
	select {
	case a.available <- struct{}{}:
		defer func() { <-a.available }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if existing, err := a.read(name); err == nil {
		if !bytes.Equal(existing, raw) {
			return audit.ErrDuplicateConflict
		}
		return a.syncDirectory(a.root)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errCredentials
	}
	entries, err := a.retainedEntries(ctx)
	if err != nil {
		return err
	}
	if len(entries) >= 256 {
		return audit.ErrBackpressure
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errCredentials
	}
	temporary := ".pending-" + hex.EncodeToString(random[:])
	file, err := a.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errCredentials
	}
	defer a.root.Remove(temporary)
	_, writeErr := file.Write(raw)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errCredentials
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.root.Link(temporary, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return errCredentials
		}
		existing, readErr := a.read(name)
		if readErr != nil || !bytes.Equal(existing, raw) {
			return audit.ErrDuplicateConflict
		}
	}
	return a.syncDirectory(a.root)
}

// Caller holds the filesystem gate. A staging name cannot be the sole custody
// of a primary side effect: Link and directory acknowledgement precede append.
// Remove only exact private staging names, not complete retained record files.
func (a *localAuditCustody) retainedEntries(ctx context.Context) ([]os.DirEntry, error) {
	directory, err := a.root.Open(".")
	if err != nil {
		return nil, errCredentials
	}
	entries, readErr := directory.ReadDir(258)
	closeErr := directory.Close()
	// One interrupted publication can leave the 256th retained batch plus its
	// staging alias. Read one extra entry to reject states above that bound.
	if (readErr != nil && readErr != io.EOF) || closeErr != nil || len(entries) > 257 {
		return nil, audit.ErrBackpressure
	}
	retained := make([]os.DirEntry, 0, len(entries))
	cleaned := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		if !strings.HasPrefix(name, ".pending-") {
			retained = append(retained, entry)
			continue
		}
		suffix := strings.TrimPrefix(name, ".pending-")
		decoded, err := hex.DecodeString(suffix)
		info, statErr := a.root.Lstat(name)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != suffix || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > auditCustodyBatchBytes {
			return nil, errCredentials
		}
		if err := a.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, errCredentials
		}
		cleaned = true
	}
	if len(retained) > 256 {
		return nil, audit.ErrBackpressure
	}
	if cleaned && a.syncDirectory(a.root) != nil {
		return nil, errCredentials
	}
	return retained, nil
}

// Reconcile resubmits at most 256 retained batches through the existing native
// append protocol. It never invokes HIBP, generates events or changes identity.
func (a *localAuditCustody) Reconcile(ctx context.Context) error {
	if ctx == nil || a == nil || a.root == nil {
		return errLocalProfile
	}
	// Serialize only local staging cleanup; release before native append IO.
	select {
	case a.available <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	entries, err := a.retainedEntries(ctx)
	<-a.available
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		raw, err := a.read(name)
		if err != nil || name != auditCustodyName(raw) {
			return errCredentials
		}
		var encoded []json.RawMessage
		if json.Unmarshal(raw, &encoded) != nil || len(encoded) < 1 || len(encoded) > 2 {
			return errCredentials
		}
		records := make([]audit.Record, len(encoded))
		for i, item := range encoded {
			records[i], err = audit.ParseCanonicalJSON(item, audit.DefaultLimits())
			if err != nil {
				return errCredentials
			}
			records[i], err = a.privacy.Redact(ctx, records[i])
			if err != nil {
				return errCredentials
			}
			canonical, err := audit.CanonicalJSON(records[i])
			if err != nil || !bytes.Equal(item, canonical) {
				// Recovery never repairs content or replaces original record IDs.
				return errCredentials
			}
		}
		if _, err := a.AppendBatch(ctx, records); err != nil {
			return err
		}
	}
	return nil
}
