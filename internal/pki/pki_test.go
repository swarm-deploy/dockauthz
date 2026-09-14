package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestCertificateFlow(t *testing.T) {
	dir := t.TempDir()
	var output bytes.Buffer
	require.NoError(t, Run([]string{"ca", "--name", "test-ca", "--out", dir}, &output, io.Discard))
	caPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	ca := readCertificate(t, caPath)
	assert.True(t, ca.IsCA)
	assert.True(t, ca.BasicConstraintsValid)
	assert.NotZero(t, ca.KeyUsage&x509.KeyUsageCertSign)
	assert.NotZero(t, ca.KeyUsage&x509.KeyUsageCRLSign)
	assert.InDelta(t, 3650*24, ca.NotAfter.Sub(time.Now()).Hours(), 1)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, tc := range []struct {
		kind, certFile, keyFile string
		eku                     x509.ExtKeyUsage
	}{
		{"client", "cert.pem", "key.pem", x509.ExtKeyUsageClientAuth},
		{"server", "server-cert.pem", "server-key.pem", x509.ExtKeyUsageServerAuth},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			out := filepath.Join(dir, tc.kind)
			args := []string{tc.kind, "--name", "cloud-secrets", "--ca-cert", caPath, "--ca-key", keyPath, "--out", out}
			if tc.kind == "server" {
				args = append(args, "--dns", "manager.example.com", "--dns", "manager", "--ip", "10.0.0.10", "--ip", "::1")
			}
			require.NoError(t, Run(args, &output, io.Discard))
			cert := readCertificate(t, filepath.Join(out, tc.certFile))
			assert.Equal(t, "cloud-secrets", cert.Subject.CommonName)
			assert.Equal(t, []x509.ExtKeyUsage{tc.eku}, cert.ExtKeyUsage)
			_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{tc.eku}})
			require.NoError(t, err)
			assert.InDelta(t, 365*24, cert.NotAfter.Sub(time.Now()).Hours(), 1)
			if tc.kind == "server" {
				assert.Equal(t, []string{"manager.example.com", "manager"}, cert.DNSNames)
				assert.True(t, cert.IPAddresses[0].Equal(net.ParseIP("10.0.0.10")))
				assert.True(t, cert.IPAddresses[1].Equal(net.ParseIP("::1")))
			}
			for name, mode := range map[string]os.FileMode{tc.certFile: 0644, tc.keyFile: 0600, "ca.pem": 0644} {
				info, err := os.Stat(filepath.Join(out, name))
				require.NoError(t, err)
				assert.Equal(t, mode, info.Mode().Perm())
			}
			before, err := os.ReadFile(filepath.Join(out, tc.keyFile))
			require.NoError(t, err)
			require.Error(t, Run(args, &output, io.Discard))
			after, err := os.ReadFile(filepath.Join(out, tc.keyFile))
			require.NoError(t, err)
			assert.Equal(t, before, after)
			require.NoError(t, Run(append(args, "--force", "--days", "10"), &output, io.Discard))
			replacement := readCertificate(t, filepath.Join(out, tc.certFile))
			assert.NotEqual(t, cert.SerialNumber, replacement.SerialNumber)
			assert.InDelta(t, 10*24, replacement.NotAfter.Sub(time.Now()).Hours(), 1)
		})
	}
	for name, mode := range map[string]os.FileMode{"ca.pem": 0644, "ca-key.pem": 0600} {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode().Perm())
	}
	assert.NotContains(t, output.String(), "PRIVATE KEY")
}

func TestInvalidCertificateOptions(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"ca"}, {"ca", "--name", "ca", "--out", "unused", "--days", "0"}, {"ca", "--name", "ca", "--out", "unused", "--days", "-1"}, {"server", "--name", "manager", "--out", "unused"}, {"server", "--name", "manager", "--out", "unused", "--ip", "bad"}, {"server", "--name", "manager", "--out", "unused", "--dns", "bad/name"}, {"client", "--name", "client", "--out", "unused", "extra"}} {
		t.Run(stringJoin(args), func(t *testing.T) { require.Error(t, Run(args, io.Discard, io.Discard)) })
	}
}
func stringJoin(args []string) string {
	var b bytes.Buffer
	for _, s := range args {
		b.WriteString(s)
		b.WriteByte(' ')
	}
	return b.String()
}

func TestForceReplacesSymlinkWithoutFollowing(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sensitive")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0600))
	out := filepath.Join(dir, "out")
	require.NoError(t, os.Mkdir(out, 0700))
	require.NoError(t, os.Symlink(target, filepath.Join(out, "ca-key.pem")))
	require.Error(t, Generate(Options{Kind: "ca", Name: "ca", Out: out}))
	require.NoError(t, Generate(Options{Kind: "ca", Name: "ca", Out: out, Force: true}))
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(data))
}
