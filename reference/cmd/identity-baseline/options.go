package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"net/url"
	"strconv"
)

var errLocalProfile = errors.New("baseline: explicit local capture configuration required")

type options struct {
	operation, directory, dsnFile, origin, address string
	localCapture                                   bool
	passwordReset                                  bool
	passwordChange                                 bool
}

func parseOptions(args []string) (options, error) {
	var out options
	if len(args) == 0 || len(args) > 32 {
		return out, errLocalProfile
	}
	out.operation = args[0]
	if out.operation != "init" && out.operation != "migrate" && out.operation != "serve" && out.operation != "exercise" && out.operation != "exercise-reset" && out.operation != "exercise-change" && out.operation != "reconcile-audits" {
		return out, errLocalProfile
	}
	flags := flag.NewFlagSet("identity-baseline", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&out.directory, "directory", "", "private configuration and mailbox directory")
	flags.StringVar(&out.dsnFile, "dsn-file", "", "private PostgreSQL DSN file")
	flags.StringVar(&out.origin, "origin", "https://127.0.0.1:8443", "exact loopback HTTPS origin")
	flags.BoolVar(&out.localCapture, "local-capture", false, "explicit local file-delivery profile, never a production mode")
	flags.BoolVar(&out.passwordReset, "password-reset", false, "explicit emailed-capability reset profile")
	flags.BoolVar(&out.passwordChange, "password-change", false, "explicit fresh-password verification and revoke-all change profile")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || !out.localCapture || out.directory == "" || len(out.directory) > 4096 || len(out.dsnFile) > 4096 {
		return options{}, errLocalProfile
	}
	if len(out.origin) > 256 {
		return options{}, errLocalProfile
	}
	u, err := url.Parse(out.origin)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return options{}, errLocalProfile
	}
	host, port, err := net.SplitHostPort(u.Host)
	n, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return options{}, errLocalProfile
	}
	out.address = u.Host
	if host == "localhost" {
		// Do not let name resolution turn the selected local listener into an
		// externally reachable bind. The public origin remains unchanged.
		out.address = net.JoinHostPort("127.0.0.1", port)
	}
	if out.operation == "exercise-reset" && !out.passwordReset || out.operation == "exercise-change" && !out.passwordChange || out.operation == "reconcile-audits" && !out.passwordReset && !out.passwordChange {
		return options{}, errLocalProfile
	}
	if out.operation != "init" && out.operation != "exercise" && out.operation != "exercise-reset" && out.operation != "exercise-change" && out.dsnFile == "" {
		return options{}, errLocalProfile
	}
	return out, nil
}
