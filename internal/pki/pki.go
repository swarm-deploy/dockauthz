// Package pki issues Docker-compatible certificates using only the standard library.
package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	// Kind is ca, server or client.
	Kind string
	// Name becomes the subject common name.
	Name string
	// Out is the destination directory.
	Out string
	// Days overrides the 3650-day CA or 365-day leaf lifetime; zero selects default.
	Days int
	// DNS contains every requested server DNS SAN.
	DNS []string
	// IP contains every requested server IP SAN.
	IP []string
	// CACert is the signing CA PEM file for leaf issuance.
	CACert string
	// CAKey is the signing CA private key PEM file for leaf issuance.
	CAKey string
	// Force explicitly allows replacing existing output files.
	Force bool
}

type output struct {
	name string
	data []byte
	mode os.FileMode
}

const (
	certKindCA     = "ca"
	certKindServer = "server"
	certKindClient = "client"
	defaultDays    = 365
	defaultCADays  = 3650
	maxDays        = 36500
	serialBits     = 159
	keyBits        = 3072
)

// Generate writes certificates with mode 0644 and private keys with mode 0600.
func Generate(o Options) error {
	if o.Kind != certKindCA && o.Kind != certKindServer && o.Kind != certKindClient {
		return errors.New("certificate kind must be ca, server or client")
	}
	if strings.TrimSpace(o.Name) == "" || o.Out == "" {
		return errors.New("--name and --out are required")
	}
	if o.Days == 0 {
		o.Days = defaultDays
		if o.Kind == certKindCA {
			o.Days = defaultCADays
		}
	}
	if o.Days < 1 || o.Days > maxDays {
		return errors.New("--days must be between 1 and 36500")
	}
	if o.Kind == certKindServer && len(o.DNS)+len(o.IP) == 0 {
		return errors.New("server certificate requires at least one --dns or --ip SAN")
	}
	var ips []net.IP
	for _, value := range o.IP {
		ip := net.ParseIP(value)
		if ip == nil {
			return errors.New("invalid IP SAN")
		}
		ips = append(ips, ip)
	}
	for _, value := range o.DNS {
		if !validDNS(value) {
			return errors.New("invalid DNS SAN")
		}
	}
	certName, keyName := "cert.pem", "key.pem"
	if o.Kind == certKindCA {
		certName, keyName = "ca.pem", "ca-key.pem"
	}
	if o.Kind == certKindServer {
		certName, keyName = "server-cert.pem", "server-key.pem"
	}
	names := []string{certName, keyName}
	if o.Kind != certKindCA {
		names = append(names, "ca.pem")
	}
	if !o.Force {
		for _, name := range names {
			if _, err := os.Lstat(filepath.Join(o.Out, name)); err == nil {
				return errors.New("output file exists; use --force to replace it")
			} else if !errors.Is(err, os.ErrNotExist) {
				return errors.New("cannot inspect output path")
			}
		}
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		return errors.New("cannot generate certificate serial")
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.Name},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(o.Days) * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	var parent *x509.Certificate
	var signer *rsa.PrivateKey
	var caPEM []byte
	if o.Kind == certKindCA {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		parent = template
	} else {
		parent, signer, caPEM, err = loadCA(o.CACert, o.CAKey)
		if err != nil {
			return err
		}
		if now.Before(parent.NotBefore) || template.NotAfter.After(parent.NotAfter) {
			return errors.New("requested lifetime is outside CA validity")
		}
		if o.Kind == certKindServer {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.DNSNames = o.DNS
			template.IPAddresses = ips
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return errors.New("cannot generate RSA private key")
	}
	if o.Kind == certKindCA {
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		return errors.New("cannot sign certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errors.New("cannot encode private key")
	}
	files := []output{
		{certName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644},
		{keyName, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600},
	}
	if o.Kind != certKindCA {
		files = append(files, output{"ca.pem", caPEM, 0644})
	}
	return writeBundle(o.Out, files, o.Force)
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	fail := errors.New("invalid CA certificate or signing key")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fail
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, nil, fail
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, nil, fail
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, fail
	}
	block, rest = pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, nil, fail
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return nil, nil, nil, fail
	}
	if err != nil || key == nil || key.Validate() != nil {
		return nil, nil, nil, fail
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, nil, fail
	}
	return cert, key, certPEM, nil
}

func validDNS(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	value = strings.TrimSuffix(value, ".")
	value = strings.TrimPrefix(value, "*.")
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func writeBundle(dir string, files []output, force bool) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create certificate directory")
	}
	var temps, created []string
	defer func() {
		for _, name := range temps {
			_ = os.Remove(name)
		}
	}()
	for _, file := range files {
		f, err := os.CreateTemp(dir, ".dockauthz-pki-*")
		if err != nil {
			return errors.New("cannot stage certificate bundle")
		}
		temps = append(temps, f.Name())
		_, writeErr := f.Write(file.data)
		modeErr := f.Chmod(file.mode)
		syncErr := f.Sync()
		closeErr := f.Close()
		if errors.Join(writeErr, modeErr, syncErr, closeErr) != nil {
			return errors.New("cannot write certificate bundle")
		}
	}
	for i, file := range files {
		target := filepath.Join(dir, file.name)
		var err error
		if force {
			err = os.Rename(temps[i], target)
		} else {
			err = os.Link(temps[i], target)
		}
		if err != nil {
			if !force {
				for _, name := range created {
					_ = os.Remove(name)
				}
			}
			return errors.New("cannot publish certificate bundle; existing files require --force")
		}
		created = append(created, target)
	}
	return nil
}
