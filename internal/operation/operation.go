// Package operation resolves the deliberately small, supported Docker API surface.
package operation

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

type Operation struct {
	// Resource is a singular, supported Docker resource name.
	Resource string
	// Action is the normalized API action.
	Action string
	// ID is the resource identifier or name, when present.
	ID string
	// Version is the API version without its leading v, or empty.
	Version string
	// Query contains validated query syntax; policy checks its semantics.
	Query url.Values
}

var apiVersion = regexp.MustCompile(`^v[1-9][0-9]*\.[0-9]+$`)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// Supports reports the explicitly implemented resource/action combinations.
func Supports(resource, action string) bool {
	switch resource {
	case "service":
		return action == "list" || action == "inspect" || action == "create" || action == "update" || action == "delete"
	case "secret":
		return action == "list" || action == "inspect" || action == "create" || action == "delete"
	case "task", "node":
		return action == "list" || action == "inspect"
	}
	return false
}

// Resolve rejects ambiguous paths instead of cleaning or partially matching them.
func Resolve(method, uri string) (Operation, error) {
	bad := errors.New("unknown or invalid Docker operation")
	u, err := url.ParseRequestURI(uri)
	if err != nil || !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.ContainsAny(uri, "#\\\r\n\t ") || strings.Contains(u.EscapedPath(), "%") {
		return Operation{}, bad
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Operation{}, bad
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	op := Operation{Query: query}
	if len(parts) > 0 && apiVersion.MatchString(parts[0]) {
		op.Version = parts[0][1:]
		parts = parts[1:]
	}
	if len(parts) < 1 || len(parts) > 3 {
		return Operation{}, bad
	}
	switch parts[0] {
	case "services":
		op.Resource = "service"
	case "secrets":
		op.Resource = "secret"
	case "tasks":
		op.Resource = "task"
	case "nodes":
		op.Resource = "node"
	default:
		return Operation{}, bad
	}
	switch {
	case len(parts) == 1 && method == "GET":
		op.Action = "list"
	case len(parts) == 2 && parts[1] == "create" && method == "POST":
		op.Action = "create"
	case len(parts) == 2 && method == "GET":
		op.Action, op.ID = "inspect", parts[1]
	case len(parts) == 2 && method == "DELETE":
		op.Action, op.ID = "delete", parts[1]
	case len(parts) == 3 && parts[2] == "update" && method == "POST":
		op.Action, op.ID = "update", parts[1]
	default:
		return Operation{}, bad
	}
	if !Supports(op.Resource, op.Action) || (op.Action != "list" && op.Action != "create" && !identifier.MatchString(op.ID)) {
		return Operation{}, bad
	}
	return op, nil
}
