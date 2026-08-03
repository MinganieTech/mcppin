package mcpexport

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/MinganieTech/mcppin/internal/mcppin"
)

// ServerConfig is one stdio server as a client configuration declares it.
type ServerConfig struct {
	// ID is the key the configuration filed this server under. It is the
	// identity the manifest carries, because it is the one thing about a server
	// that the server itself does not get to choose.
	ID      string
	Command string
	Args    []string
	Env     map[string]string
}

// ReadConfig reads the mcpServers object every stdio client configuration
// shares, and refuses anything it cannot capture rather than skipping it: a
// manifest that quietly omits a server is a manifest that approves an agent's
// surface without having seen it.
func ReadConfig(path string) ([]ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value, err := mcppin.DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: the configuration is not a JSON object", path)
	}
	declared, ok := root["mcpServers"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: the configuration has no mcpServers object", path)
	}

	ids := make([]string, 0, len(declared))
	for id := range declared {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	servers := make([]ServerConfig, 0, len(ids))
	for _, id := range ids {
		entry, ok := declared[id].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: server %q is not an object", path, id)
		}
		if url, remote := entry["url"].(string); remote && url != "" {
			return nil, fmt.Errorf("%s: server %q is served over %s; this exporter speaks stdio only",
				path, id, url)
		}
		command, _ := entry["command"].(string)
		if command == "" {
			return nil, fmt.Errorf("%s: server %q has no command", path, id)
		}
		server := ServerConfig{ID: id, Command: command}
		if raw, present := entry["args"]; present {
			// Present and not an array is a configuration whose author meant
			// something this build would silently drop, and the command it
			// would run is not the one they wrote.
			args, ok := raw.([]any)
			if !ok {
				return nil, fmt.Errorf("%s: server %q has args that are not an array", path, id)
			}
			for i, rawArg := range args {
				arg, ok := rawArg.(string)
				if !ok {
					return nil, fmt.Errorf("%s: server %q argument %d is not a string", path, id, i+1)
				}
				server.Args = append(server.Args, arg)
			}
		}
		if rawEnv, present := entry["env"]; present {
			env, ok := rawEnv.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: server %q has an env that is not an object", path, id)
			}
			server.Env = make(map[string]string, len(env))
			for key, rawValue := range env {
				value, ok := rawValue.(string)
				if !ok {
					return nil, fmt.Errorf("%s: server %q env %q is not a string", path, id, key)
				}
				server.Env[key] = value
			}
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil, errors.New("the configuration declares no server")
	}
	return servers, nil
}
