package pki

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

type repeated []string

func (r *repeated) String() string         { return "" }
func (r *repeated) Set(value string) error { *r = append(*r, value); return nil }

// Run implements the three certificate commands without exposing key material.
func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: dockauthz-cert ca|server|client [flags]")
	}
	o := Options{Kind: args[0]}
	if o.Kind != "ca" && o.Kind != "server" && o.Kind != "client" {
		return errors.New("unknown certificate command")
	}
	f := flag.NewFlagSet("dockauthz-cert "+o.Kind, flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&o.Name, "name", "", "certificate common name (required)")
	f.StringVar(&o.Out, "out", "", "output directory (required)")
	defaultDays := 365
	if o.Kind == "ca" {
		defaultDays = 3650
	}
	f.IntVar(&o.Days, "days", defaultDays, "certificate lifetime in days")
	f.BoolVar(&o.Force, "force", false, "replace existing output files")
	if o.Kind != "ca" {
		f.StringVar(&o.CACert, "ca-cert", "", "CA certificate PEM path")
		f.StringVar(&o.CAKey, "ca-key", "", "CA private key PEM path")
	}
	var dns, ips repeated
	if o.Kind == "server" {
		f.Var(&dns, "dns", "DNS SAN (repeatable)")
		f.Var(&ips, "ip", "IP SAN (repeatable)")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if o.Days <= 0 {
		return errors.New("--days must be positive")
	}
	o.DNS = dns
	o.IP = ips
	if err := Generate(o); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "Certificate bundle created in", o.Out)
	return err
}
