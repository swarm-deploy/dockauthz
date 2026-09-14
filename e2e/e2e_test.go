package e2e

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/swarm"
	dock "github.com/moby/moby/client"
	"github.com/swarm-deploy/dockertester"
)

const (
	pluginName  = "dockauthz:e2e"
	serviceName = "e2e-service"
	secretAName = "e2e-secret-a"
	secretBName = "e2e-secret-b"
)

func TestDockauthzManagedPlugin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	root := repoRoot(t)
	work, err := os.MkdirTemp("/tmp", "daz-e2e-*")
	requireNoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(work)
	})

	pluginPackage := filepath.Join(root, "dist", "dockauthz-plugin-linux-amd64.tar.gz")
	if _, err := os.Stat(pluginPackage); err != nil {
		t.Fatalf("e2e requires built plugin package %s: %v", pluginPackage, err)
	}

	certsDir := filepath.Join(work, "certs")
	t.Log("generating e2e certificates")
	generateCerts(ctx, t, root, certsDir)
	pluginDir := filepath.Join(work, "plugin")
	t.Log("extracting built plugin package")
	extractTarGz(t, pluginPackage, pluginDir)

	containerName := fmt.Sprintf("dockauthz-e2e-%d", os.Getpid())
	t.Log("starting privileged docker:dind container")
	docker(ctx, t, "", "run", "-d", "--privileged", "--init", "--name", containerName,
		"-p", "127.0.0.1::2375",
		"-p", "127.0.0.1::2376",
		"docker:dind", "sleep", "infinity")
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
	})

	docker(ctx, t, "", "cp", certsDir+"/.", containerName+":/certs")
	docker(ctx, t, "", "cp", pluginDir, containerName+":/workspace-plugin")
	dx(ctx, t, containerName, "mkdir -p /etc/dockauthz")

	t.Log("starting nested dockerd without authorization plugin")
	startDockerd(ctx, t, containerName, false)
	bootstrap := newClient(t, "tcp://127.0.0.1:"+mappedPort(ctx, t, containerName, "2375/tcp"))
	waitReady(ctx, t, containerName, bootstrap)

	sw := dockertester.NewSwarmTester(bootstrap)
	_, err = bootstrap.SwarmInit(ctx, dock.SwarmInitOptions{ListenAddr: "0.0.0.0:2377"})
	requireNoError(t, err)
	sw.RequireSwarmMode(ctx, t)

	secrets := dockertester.NewSecretTester(bootstrap)
	secretAID, err := secrets.CreateSecret(ctx, secretAName, []byte("current-a"))
	requireNoError(t, err)
	secretBID, err := secrets.CreateSecret(ctx, secretBName, []byte("current-b"))
	requireNoError(t, err)

	services := dockertester.NewServiceTester(bootstrap)
	serviceID, err := services.Deploy(ctx, serviceSpec(secretAID, secretAName))
	requireNoError(t, err)

	t.Log("installing managed plugin with permissive policy")
	installPlugin(ctx, t, root, containerName, "config.yaml")
	restartWithPlugin(ctx, t, containerName)
	waitReadyExec(ctx, t, containerName)

	t.Run("unidentified access", func(t *testing.T) {
		dx(ctx, t, containerName, "docker service ls")
		dx(ctx, t, containerName, "docker service inspect "+serviceName)
	})

	t.Log("installing managed plugin with strict policy")
	installPlugin(ctx, t, root, containerName, "config-strict.yaml")
	restartWithPlugin(ctx, t, containerName)
	waitReadyExec(ctx, t, containerName)

	host := "tcp://127.0.0.1:" + mappedPort(ctx, t, containerName, "2376/tcp")
	admin := newTLSClient(t, host, filepath.Join(certsDir, "admin"))
	mutator := newTLSClient(t, host, filepath.Join(certsDir, "mutator"))
	adminServices := dockertester.NewServiceTester(admin)
	adminSecrets := dockertester.NewSecretTester(admin)
	adminSwarm := dockertester.NewSwarmTester(admin)
	mutatorServices := dockertester.NewServiceTester(mutator)
	mutatorSecrets := dockertester.NewSecretTester(mutator)
	_ = adminServices
	_ = adminSecrets
	_ = mutatorServices
	_ = mutatorSecrets
	adminSwarm.RequireSwarmMode(ctx, t)

	t.Run("admin full access", func(t *testing.T) {
		_, err := admin.ServiceList(ctx, dock.ServiceListOptions{})
		requireNoError(t, err)
		_, err = admin.SecretList(ctx, dock.SecretListOptions{})
		requireNoError(t, err)
	})

	t.Run("mutator service list inspect", func(t *testing.T) {
		_, err := mutator.ServiceList(ctx, dock.ServiceListOptions{})
		requireNoError(t, err)
		_, err = mutator.ServiceInspect(ctx, serviceID, dock.ServiceInspectOptions{})
		requireNoError(t, err)
	})

	t.Run("deny unknown endpoint", func(t *testing.T) {
		_, err := mutator.ImageList(ctx, dock.ImageListOptions{})
		requireError(t, err)
	})

	t.Run("deny secret access", func(t *testing.T) {
		_, err := mutator.SecretList(ctx, dock.SecretListOptions{})
		requireError(t, err)
	})

	t.Run("allow secrets-only update", func(t *testing.T) {
		err := updateService(ctx, mutator, serviceID, "", secretBID, secretBName)
		requireNoError(t, err)
	})

	t.Run("deny image and secrets update", func(t *testing.T) {
		err := updateService(ctx, mutator, serviceID, "nginx:2", secretAID, secretAName)
		requireError(t, err)
	})

	t.Run("final service state", func(t *testing.T) {
		svc, err := admin.ServiceInspect(ctx, serviceID, dock.ServiceInspectOptions{})
		requireNoError(t, err)
		gotImage := svc.Service.Spec.TaskTemplate.ContainerSpec.Image
		if !strings.HasPrefix(gotImage, "nginx:1") {
			t.Fatalf("final image = %q, want nginx:1", gotImage)
		}
		refs := svc.Service.Spec.TaskTemplate.ContainerSpec.Secrets
		if len(refs) != 1 || refs[0].SecretName != secretBName {
			t.Fatalf("final secrets = %#v, want only %s", refs, secretBName)
		}
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	requireNoError(t, err)
	return filepath.Dir(wd)
}

func generateCerts(ctx context.Context, t *testing.T, root, certsDir string) {
	t.Helper()
	cert := func(args ...string) {
		t.Helper()
		cmdArgs := append([]string{"run", "./cmd/dockauthz-cert"}, args...)
		run(ctx, t, root, append([]string{"go"}, cmdArgs...)...)
	}
	cert("ca", "--name", "e2e-ca", "--out", filepath.Join(certsDir, "ca"))
	cert("server", "--name", "docker-dind", "--out", filepath.Join(certsDir, "server"),
		"--ca-cert", filepath.Join(certsDir, "ca", "ca.pem"),
		"--ca-key", filepath.Join(certsDir, "ca", "ca-key.pem"),
		"--dns", "localhost", "--ip", "127.0.0.1")
	cert("client", "--name", "e2e-admin", "--out", filepath.Join(certsDir, "admin"),
		"--ca-cert", filepath.Join(certsDir, "ca", "ca.pem"),
		"--ca-key", filepath.Join(certsDir, "ca", "ca-key.pem"))
	cert("client", "--name", "e2e-mutator", "--out", filepath.Join(certsDir, "mutator"),
		"--ca-cert", filepath.Join(certsDir, "ca", "ca.pem"),
		"--ca-key", filepath.Join(certsDir, "ca", "ca-key.pem"))
}

func startDockerd(ctx context.Context, t *testing.T, containerName string, withPlugin bool) {
	t.Helper()
	args := []string{"dockerd", "--host=unix:///var/run/docker.sock", "--host=tcp://0.0.0.0:2375"}
	logFile := "/var/log/dockerd-setup.log"
	if withPlugin {
		args = append(args,
			"--host=tcp://0.0.0.0:2376",
			"--tlsverify",
			"--tlscacert=/certs/server/ca.pem",
			"--tlscert=/certs/server/server-cert.pem",
			"--tlskey=/certs/server/server-key.pem",
			"--authorization-plugin="+pluginName,
		)
		logFile = "/var/log/dockerd-authz.log"
	}
	dx(ctx, t, containerName, strings.Join(args, " ")+" >"+logFile+" 2>&1 &")
}

func restartWithPlugin(ctx context.Context, t *testing.T, containerName string) {
	t.Helper()
	dx(ctx, t, containerName, "pkill -9 dockerd || true")
	dx(ctx, t, containerName, "rm -f /var/run/docker.pid")
	startDockerd(ctx, t, containerName, true)
}

func installPlugin(ctx context.Context, t *testing.T, root, containerName, configName string) {
	t.Helper()
	dx(ctx, t, containerName, "docker plugin disable "+pluginName+" --force >/dev/null 2>&1 || true")
	dx(ctx, t, containerName, "docker plugin rm "+pluginName+" >/dev/null 2>&1 || true")
	docker(ctx, t, "", "cp", filepath.Join(root, "e2e", configName), containerName+":/etc/dockauthz/config.yaml")
	dx(ctx, t, containerName, "docker plugin create "+pluginName+" /workspace-plugin")
	dx(ctx, t, containerName, "docker plugin enable "+pluginName)
}

func waitReady(ctx context.Context, t *testing.T, containerName string, client *dock.Client) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for {
		_, err := client.Info(ctx, dock.InfoOptions{})
		if err == nil {
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			logs := dxAllowError(ctx, containerName, "tail -200 /var/log/dockerd-setup.log /var/log/dockerd-authz.log 2>/dev/null")
			t.Fatalf("nested Docker daemon never became ready: %v\n%s", lastErr, logs)
		}
		time.Sleep(time.Second)
	}
}

func waitReadyExec(ctx context.Context, t *testing.T, containerName string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var lastOut string
	for {
		out, err := dxResult(ctx, containerName, "docker info")
		if err == nil {
			return
		}
		lastOut = out
		if time.Now().After(deadline) {
			logs := dxAllowError(ctx, containerName, "tail -200 /var/log/dockerd-setup.log /var/log/dockerd-authz.log 2>/dev/null")
			t.Fatalf("nested Docker daemon never became ready via unix socket: %s\n%s", lastOut, logs)
		}
		time.Sleep(time.Second)
	}
}

func serviceSpec(secretID, secretName string) swarm.ServiceSpec {
	return swarm.ServiceSpec{
		Annotations: swarm.Annotations{Name: serviceName},
		TaskTemplate: swarm.TaskSpec{
			ContainerSpec: &swarm.ContainerSpec{
				Image:   "nginx:1",
				Secrets: []*swarm.SecretReference{dockertester.SecretRef(secretName, secretName, secretID)},
			},
			RestartPolicy: &swarm.RestartPolicy{Condition: swarm.RestartPolicyConditionNone},
		},
		Mode: swarm.ServiceMode{Replicated: &swarm.ReplicatedService{Replicas: uint64Ptr(1)}},
	}
}

func updateService(ctx context.Context, client *dock.Client, serviceID, imageName, secretID, secretName string) error {
	svc, err := client.ServiceInspect(ctx, serviceID, dock.ServiceInspectOptions{})
	if err != nil {
		return err
	}
	spec := svc.Service.Spec
	spec.TaskTemplate.ContainerSpec.Secrets = []*swarm.SecretReference{dockertester.SecretRef(secretName, secretName, secretID)}
	if imageName != "" {
		spec.TaskTemplate.ContainerSpec.Image = imageName
	}
	_, err = client.ServiceUpdate(ctx, serviceID, dock.ServiceUpdateOptions{
		Version:          svc.Service.Version,
		Spec:             spec,
		RegistryAuthFrom: swarm.RegistryAuthFromSpec,
	})
	return err
}

func newClient(t *testing.T, host string) *dock.Client {
	t.Helper()
	client, err := dock.NewClientWithOpts(dock.WithHost(host), dock.WithAPIVersionNegotiation())
	requireNoError(t, err)
	return client
}

func newTLSClient(t *testing.T, host, certDir string) *dock.Client {
	t.Helper()
	client, err := dock.NewClientWithOpts(
		dock.WithHost(host),
		dock.WithTLSClientConfig(filepath.Join(certDir, "ca.pem"), filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem")),
		dock.WithAPIVersionNegotiation(),
	)
	requireNoError(t, err)
	return client
}

func mappedPort(ctx context.Context, t *testing.T, containerName, privatePort string) string {
	t.Helper()
	out := docker(ctx, t, "", "port", containerName, privatePort)
	_, port, err := net.SplitHostPort(strings.TrimSpace(out))
	requireNoError(t, err)
	return port
}

func docker(ctx context.Context, t *testing.T, dir string, args ...string) string {
	t.Helper()
	return run(ctx, t, dir, append([]string{"docker"}, args...)...)
}

func run(ctx context.Context, t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func dx(ctx context.Context, t *testing.T, containerName, script string) string {
	t.Helper()
	return docker(ctx, t, "", "exec", containerName, "sh", "-c", script)
}

func dxAllowError(ctx context.Context, containerName, script string) string {
	out, _ := dxResult(ctx, containerName, script)
	return out
}

func dxResult(ctx context.Context, containerName, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func extractTarGz(t *testing.T, source, target string) {
	t.Helper()
	file, err := os.Open(source)
	requireNoError(t, err)
	defer file.Close()
	gzr, err := gzip.NewReader(file)
	requireNoError(t, err)
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return
		}
		requireNoError(t, err)
		path := filepath.Join(target, header.Name)
		if !strings.HasPrefix(path, filepath.Clean(target)+string(os.PathSeparator)) {
			t.Fatalf("unsafe tar path %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			requireNoError(t, os.MkdirAll(path, os.FileMode(header.Mode)))
		case tar.TypeReg:
			requireNoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			dst, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			requireNoError(t, err)
			_, err = io.Copy(dst, tr)
			closeErr := dst.Close()
			requireNoError(t, err)
			requireNoError(t, closeErr)
		}
	}
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
}
