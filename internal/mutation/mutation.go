// Package mutation proves that every changed ServiceSpec field is permitted.
package mutation

//go:generate go run ./generate

import (
	"errors"

	"github.com/moby/moby/api/types/swarm"
	"github.com/swarm-deploy/dockauthz/internal/specjson"
)

// Validate replaces permitted subtrees in a fresh decode of the request, then
// compares every typed field. Fresh decoding preserves nil/empty distinctions.
func Validate(current swarm.ServiceSpec, requested []byte, allowed []string) error {
	var next swarm.ServiceSpec
	if err := specjson.Decode(requested, &next); err != nil {
		return err
	}
	if len(allowed) == 0 {
		return errors.New("empty mutation field set")
	}
	for _, field := range allowed {
		switch field {
		case "container.secrets", "container.image":
			before, after := current.TaskTemplate.ContainerSpec, next.TaskTemplate.ContainerSpec
			if before == nil || after == nil {
				return errors.New("mutation requires container specs on both sides")
			}
			if field == "container.secrets" {
				after.Secrets = before.Secrets
			} else {
				after.Image = before.Image
			}
		case "replicas":
			before, after := current.Mode.Replicated, next.Mode.Replicated
			if before == nil ||
				after == nil ||
				current.Mode.Global != nil ||
				current.Mode.ReplicatedJob != nil ||
				current.Mode.GlobalJob != nil ||
				next.Mode.Global != nil ||
				next.Mode.ReplicatedJob != nil ||
				next.Mode.GlobalJob != nil {
				return errors.New("replicas mutation requires replicated service mode")
			}
			after.Replicas = before.Replicas
		default:
			return errors.New("unsupported mutation field")
		}
	}
	if !equalSpec(current, next) {
		return errors.New("mutation contains fields outside allowed set")
	}
	return nil
}
