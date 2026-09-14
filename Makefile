GO ?= go
VERSION ?= dev
GOARCH ?= $(shell $(GO) env GOARCH)
PLUGIN_NAME ?= dockauthz:dev
CA_BUNDLE ?= $(firstword $(wildcard /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem))
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build test vet generate plugin-rootfs plugin-package plugin-create

build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/dockauthz ./cmd/dockauthz
	$(GO) build -trimpath -o bin/dockauthz-cert ./cmd/dockauthz-cert

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

generate:
	$(GO) generate ./internal/mutation ./internal/dockerapi

plugin-rootfs:
	test -n "$(CA_BUNDLE)" && test -f "$(CA_BUNDLE)"
	mkdir -p plugin/rootfs/usr/bin plugin/rootfs/etc/ssl/certs plugin/rootfs/etc/dockauthz plugin/rootfs/run/docker/plugins plugin/rootfs/var/run plugin/rootfs/tmp
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o plugin/rootfs/usr/bin/dockauthz ./cmd/dockauthz
	install -m 0644 "$(CA_BUNDLE)" plugin/rootfs/etc/ssl/certs/ca-certificates.crt
	touch plugin/rootfs/etc/dockauthz/config.yaml plugin/rootfs/var/run/docker.sock
	chmod 1777 plugin/rootfs/tmp

plugin-package: plugin-rootfs
	mkdir -p dist
	tar -C plugin -czf dist/dockauthz-plugin-linux-$(GOARCH).tar.gz config.json rootfs

plugin-create: plugin-rootfs
	docker plugin create $(PLUGIN_NAME) ./plugin
