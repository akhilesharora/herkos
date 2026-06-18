package register

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/akhilesharora/herkos/internal/adapters/transport/mcpstdio"
)

// discoverTimeout bounds how long DiscoverTools waits for a server to start and answer the MCP
// handshake. WrapAll skips a server that times out rather than hanging the whole command.
const discoverTimeout = 20 * time.Second

// DiscoverTools launches the MCP server `command args...`, completes the MCP stdio handshake,
// and returns the names of the tools it advertises. It is the default [Discoverer] for
// [WrapAll]. The server is always killed before returning. A server that does not speak MCP
// stdio, or that needs network/auth just to list its tools, yields an error (and WrapAll then
// leaves it un-wrapped rather than pinning an empty, deny-all allowlist).
func DiscoverTools(command string, args []string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), discoverTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Kill and reap the server on every exit path; the ctx timeout also kills it, which closes
	// stdout and unblocks a stuck ReadMessage.
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	fr := mcpstdio.NewFramer(stdout, stdin)
	const initReq = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"herkos-register","version":"0"}}}`
	if err := fr.WriteMessage([]byte(initReq)); err != nil {
		return nil, err
	}
	if _, err := readID(fr, 1); err != nil {
		return nil, err
	}
	_ = fr.WriteMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err := fr.WriteMessage([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)); err != nil {
		return nil, err
	}
	resp, err := readID(fr, 2)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return nil, fmt.Errorf("register: parse tools/list: %w", err)
	}
	names := make([]string, 0, len(parsed.Result.Tools))
	for _, t := range parsed.Result.Tools {
		if t.Name != "" {
			names = append(names, t.Name)
		}
	}
	return names, nil
}

// readID reads framed messages until one carrying the given JSON-RPC id arrives, skipping
// notifications and any server-initiated messages. It bounds the scan so a chatty server that
// never answers cannot loop forever.
func readID(fr *mcpstdio.Framer, id int) ([]byte, error) {
	for i := 0; i < 64; i++ {
		msg, err := fr.ReadMessage()
		if err != nil {
			return nil, err
		}
		var probe struct {
			ID json.Number `json:"id"`
		}
		if json.Unmarshal(msg, &probe) == nil && probe.ID.String() == fmt.Sprint(id) {
			return msg, nil
		}
	}
	return nil, fmt.Errorf("register: no response with id %d", id)
}
