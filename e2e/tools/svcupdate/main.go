// Command svcupdate issues a single, real Docker Engine ServiceUpdate call
// over mutual TLS so the e2e suite can exercise the authz plugin exactly as
// the Docker daemon does: fetch the current spec, apply one deliberate
// change, and PATCH it back with the query string Docker itself sends.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/moby/moby/api/types/swarm"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "", "https://host:port of the Docker API")
	cacert := flag.String("cacert", "", "CA certificate PEM path")
	cert := flag.String("cert", "", "client certificate PEM path")
	key := flag.String("key", "", "client private key PEM path")
	service := flag.String("service", "", "service name or ID")
	image := flag.String("image", "", "when set, also changes the container image")
	secretID := flag.String("secret-id", "", "replacement secret ID")
	secretName := flag.String("secret-name", "", "replacement secret name")
	flag.Parse()
	if *addr == "" || *cacert == "" || *cert == "" || *key == "" || *service == "" || *secretID == "" || *secretName == "" {
		return errors.New("addr, cacert, cert, key, service, secret-id and secret-name are required")
	}
	client, err := tlsClient(*cacert, *cert, *key)
	if err != nil {
		return err
	}
	id, spec, version, err := inspect(client, *addr, *service)
	if err != nil {
		return err
	}
	if spec.TaskTemplate.ContainerSpec == nil {
		return errors.New("service has no container spec")
	}
	spec.TaskTemplate.ContainerSpec.Secrets = []*swarm.SecretReference{{
		SecretID:   *secretID,
		SecretName: *secretName,
		File: &swarm.SecretReferenceFileTarget{
			Name: *secretName,
			UID:  "0",
			GID:  "0",
			Mode: 0o444,
		},
	}}
	if *image != "" {
		spec.TaskTemplate.ContainerSpec.Image = *image
	}
	code, body, err := update(client, *addr, id, version, spec)
	if err != nil {
		return err
	}
	fmt.Printf("STATUS %d\n%s\n", code, body)
	if code >= 400 {
		os.Exit(3)
	}
	return nil
}

func tlsClient(cacert, cert, key string) (*http.Client, error) {
	ca, err := os.ReadFile(cacert)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("cannot parse CA certificate")
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{pair},
			MinVersion:   tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: transport}, nil
}

func inspect(client *http.Client, addr, service string) (string, swarm.ServiceSpec, uint64, error) {
	resp, err := client.Get(addr + "/services/" + url.PathEscape(service))
	if err != nil {
		return "", swarm.ServiceSpec{}, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", swarm.ServiceSpec{}, 0, err
	}
	if resp.StatusCode >= 400 {
		return "", swarm.ServiceSpec{}, 0, fmt.Errorf("inspect failed: %d %s", resp.StatusCode, body)
	}
	var decoded struct {
		ID      string
		Version struct {
			Index uint64
		}
		Spec swarm.ServiceSpec
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", swarm.ServiceSpec{}, 0, err
	}
	return decoded.ID, decoded.Spec, decoded.Version.Index, nil
}

func update(client *http.Client, addr, id string, version uint64, spec swarm.ServiceSpec) (int, string, error) {
	payload, err := json.Marshal(spec)
	if err != nil {
		return 0, "", err
	}
	target := fmt.Sprintf("%s/services/%s/update?version=%d&registryAuthFrom=spec", addr, url.PathEscape(id), version)
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}
