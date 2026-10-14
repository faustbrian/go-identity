package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	database "github.com/faustbrian/go-postgres"
)

var baselineModules = []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runBaseline(ctx, os.Args[1:], os.Stdout); err != nil {
		// Even filesystem/transport errors can contain deployment inputs. The
		// command emits fixed outcomes, never provider or database diagnostics.
		_, _ = io.WriteString(os.Stderr, "identity baseline failed; private inputs, selected native migrations and dependencies must be valid\n")
		os.Exit(1)
	}
}

func runBaseline(ctx context.Context, args []string, output io.Writer) (err error) {
	if ctx == nil || output == nil {
		return errLocalProfile
	}
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	if o.operation == "init" {
		if err := initializeCredentials(o.directory, time.Now()); err != nil {
			return err
		}
		if o.passwordChange {
			if err := prepareChangeCredentials(o.directory); err != nil {
				return err
			}
		}
		_, err := io.WriteString(output, "private local configuration initialized; no database or listener opened\n")
		return err
	}
	secrets, err := loadCredentials(o.directory, time.Now())
	if err != nil {
		return err
	}
	if o.operation == "exercise" || o.operation == "exercise-reset" || o.operation == "exercise-change" {
		return exerciseBaseline(ctx, o, secrets, output)
	}
	if o.operation == "migrate" && o.passwordChange {
		if err := prepareChangeCredentials(o.directory); err != nil {
			return err
		}
	}
	dsn, err := readPrivateFile(o.dsnFile, 16384)
	if err != nil {
		return errCredentials
	}
	poolConfig := database.Config{DSN: string(dsn), MaxConns: 4, ConnectTimeout: 2 * time.Second, PingTimeout: 2 * time.Second, AcquireTimeout: 2 * time.Second, ShutdownTimeout: 5 * time.Second}
	parsed, err := database.ParseConfig(poolConfig)
	if err != nil || parsed.ConnConfig.RuntimeParams["search_path"] != "public" || !localDatabaseHost(parsed.ConnConfig.Host) {
		return errLocalProfile
	}
	for _, fallback := range parsed.ConnConfig.Fallbacks {
		if !localDatabaseHost(fallback.Host) {
			return errLocalProfile
		}
	}
	pool, err := database.New(ctx, poolConfig)
	if err != nil {
		return errLocalProfile
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err = errors.Join(err, pool.Close(bounded))
	}()
	sender, err := openLocalMailbox(o.directory)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, sender.Close()) }()
	if o.operation == "migrate" && (o.passwordReset || o.passwordChange) {
		// Optional migrations get a separate original request, only after the
		// unchanged baseline request is complete. Resume an existing reset
		// request directly; reverting to the smaller profile after its suffix
		// is installed would misclassify that managed history as foreign.
		if _, statErr := os.Lstat(filepath.Join(o.directory, migrationRequestName(o))); errors.Is(statErr, os.ErrNotExist) {
			base := o
			base.passwordReset = false
			base.passwordChange = false
			// A combined upgrade resumes whichever already selected predecessor
			// has original custody. Never rebuild a smaller graph over its suffix.
			if o.passwordReset && o.passwordChange {
				for _, prior := range []struct {
					name          string
					reset, change bool
				}{{"migration-request-reset.json", true, false}, {"migration-request-change.json", false, true}} {
					if _, err := os.Lstat(filepath.Join(o.directory, prior.name)); err == nil {
						base.passwordReset, base.passwordChange = prior.reset, prior.change
						break
					} else if !errors.Is(err, os.ErrNotExist) {
						return errCredentials
					}
				}
			}
			predecessor, buildErr := buildBaseline(ctx, base, secrets, pool, sender)
			if buildErr != nil {
				return buildErr
			}
			migrateErr := migrateBaselineWithRequest(ctx, predecessor.stores, o.directory, migrationRequestName(base), syncDirectory)
			closeErr := predecessor.close(ctx)
			if migrateErr != nil || closeErr != nil {
				return errors.Join(migrateErr, closeErr)
			}
		} else if statErr != nil {
			return errCredentials
		}
	}
	graph, err := buildBaseline(ctx, o, secrets, pool, sender)
	if err != nil {
		return err
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err = errors.Join(err, graph.close(bounded))
	}()
	if o.operation == "migrate" {
		if err := migrateBaselineWithRequest(ctx, graph.stores, o.directory, migrationRequestName(o), syncDirectory); err != nil {
			return err
		}
		_, err := io.WriteString(output, "migrations compatible; no account created or serving started\n")
		return err
	}
	if o.operation == "reconcile-audits" {
		bounded, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		if graph.audits == nil || graph.audits.Reconcile(bounded) != nil {
			return errLocalProfile
		}
		_, err := io.WriteString(output, "original audit records reconciled; no identity or credential effects\n")
		return err
	}
	startup, stop := context.WithTimeout(ctx, 10*time.Second)
	err = graph.features.Initialize(startup)
	if err == nil && !graph.server.Readiness(startup).Ready {
		err = errLocalProfile
	}
	stop()
	if err != nil {
		return err
	}
	return serveBaseline(ctx, graph, o, secrets, output)
}

func migrationRequestName(o options) string {
	switch {
	case o.passwordReset && o.passwordChange:
		return "migration-request-reset-change.json"
	case o.passwordChange:
		return "migration-request-change.json"
	case o.passwordReset:
		return "migration-request-reset.json"
	default:
		return "migration-request.json"
	}
}

func localDatabaseHost(host string) bool { return host == "127.0.0.1" || host == "::1" }

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() < 1 || before.Size() > maximum {
		return nil, errCredentials
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errCredentials
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, errCredentials
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, errCredentials
	}
	return content, nil
}

type operatorRequest struct {
	Command identity.CommandID      `json:"command"`
	Plan    reference.MigrationPlan `json:"plan"`
	Key     []byte                  `json:"key"`
}

func migrateBaseline(ctx context.Context, stores reference.StoreSet, directory string) error {
	return migrateBaselineWithSync(ctx, stores, directory, syncDirectory)
}

func migrateSelectedBaseline(ctx context.Context, stores reference.StoreSet, directory string, reset bool) error {
	name := "migration-request.json"
	if reset {
		name = "migration-request-reset.json"
	}
	return migrateBaselineWithRequest(ctx, stores, directory, name, syncDirectory)
}

// A filesystem acknowledgement seam allows failure proof without replacing
// the native migration owner or its database effects.
func migrateBaselineWithSync(ctx context.Context, stores reference.StoreSet, directory string, acknowledge func(string) error) error {
	return migrateBaselineWithRequest(ctx, stores, directory, "migration-request.json", acknowledge)
}

func migrateBaselineWithRequest(ctx context.Context, stores reference.StoreSet, directory, name string, acknowledge func(string) error) error {
	checked, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: baselineModules})
	if err != nil {
		return err
	}
	compatible := true
	for _, status := range checked.Statuses {
		if status.Compatibility != reference.MigrationCompatible && status.Compatibility != reference.MigrationRequired {
			return errLocalProfile
		}
		compatible = compatible && status.Compatibility == reference.MigrationCompatible
	}
	if compatible {
		return nil
	}
	// Persist the application's original operator input before side effects.
	// The existing migration owner, not this file, decides progress and recovery.
	// A rerun reuses the exact original plan/key; it never replans a partial apply.
	path := filepath.Join(directory, name)
	var request operatorRequest
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		plan, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: baselineModules})
		if err != nil {
			return err
		}
		command, err := identity.NewCommandID()
		if err != nil {
			return errLocalProfile
		}
		var rawKey [32]byte
		if _, err := rand.Read(rawKey[:]); err != nil {
			return errLocalProfile
		}
		request = operatorRequest{Command: command, Plan: plan.Plan, Key: []byte(hex.EncodeToString(rawKey[:]))}
		encoded, err := json.Marshal(request)
		if err != nil {
			return errLocalProfile
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errCredentials
		}
		_, writeErr := file.Write(encoded)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			_ = os.Remove(path) // exclusively created here, before any Apply.
			return errCredentials
		}
	} else {
		content, err := readPrivateFile(path, 1<<20)
		if err != nil || json.Unmarshal(content, &request) != nil {
			return errCredentials
		}
	}
	if len(request.Key) != 64 {
		return errCredentials
	}
	// The filename is recovery custody, not just file contents. Retry this
	// acknowledgement too when an earlier sync returned an unknown outcome.
	if acknowledge(directory) != nil {
		return errCredentials
	}
	key, err := identity.NewIdempotencyKey(request.Key)
	if err != nil {
		return errCredentials
	}
	out, err := stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: request.Command, Plan: request.Plan, IdempotencyKey: key})
	if err != nil || out.Result.State() != reference.MigrationApplied {
		return errLocalProfile
	}
	return nil
}

func serveBaseline(ctx context.Context, graph *baselineGraph, o options, secrets credentials, output io.Writer) error {
	listener, err := net.Listen("tcp", o.address)
	if err != nil {
		return errLocalProfile
	}
	defer listener.Close()
	return serveBaselineOnListener(ctx, graph, o, secrets, output, listener)
}

func serveBaselineOnListener(ctx context.Context, graph *baselineGraph, o options, secrets credentials, output io.Writer, listener net.Listener) error {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() || address.String() != o.address {
		return errLocalProfile
	}
	pair, err := tls.X509KeyPair([]byte(secrets.Certificate), []byte(secrets.PrivateKey))
	if err != nil {
		return errCredentials
	}
	lifetime, stop := context.WithCancel(ctx)
	defer stop()
	server := &http.Server{Handler: graph.server.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32768, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return lifetime }}
	failures := make(chan error, 2)
	var running sync.WaitGroup
	running.Add(2)
	go func() {
		defer running.Done()
		failures <- server.ServeTLS(listener, "", "")
	}()
	go func() {
		defer running.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-ticker.C:
				if _, err := graph.workers.ProcessDeliveryOne(lifetime, 0); err != nil && lifetime.Err() == nil {
					failures <- errLocalProfile
					return
				}
			}
		}
	}()
	var servingErr error
	if _, err := io.WriteString(output, "local HTTPS baseline ready; captured mail stays in the private directory\n"); err != nil {
		servingErr = err
	} else {
		select {
		case <-ctx.Done():
		case servingErr = <-failures:
		}
	}
	stop()
	drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(drain)
	if shutdownErr != nil {
		_ = server.Close()
	}
	joined := make(chan struct{})
	go func() { running.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-drain.Done():
		return errLocalProfile
	}
	if errors.Is(servingErr, http.ErrServerClosed) {
		servingErr = nil
	}
	return errors.Join(servingErr, shutdownErr)
}
