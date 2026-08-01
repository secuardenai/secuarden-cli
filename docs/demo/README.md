# Reproducing the terminal demo

Run from the repository root on macOS:

```bash
./docs/demo/generate.sh
```

The generator:

- builds the current Secuarden source as a `v0.2.0` binary;
- creates an isolated HOME and Git repository under `/private/tmp/secuarden-terminal-demo`;
- configures only the synthetic identity `Demo Developer <developer@example.invalid>` and the remote `https://example.invalid/acme/demo-repository.git`;
- replays the JSON files in `fixtures/` through the binary's real Claude Code hook commands;
- runs the real `events`, `report`, and `status` commands to create four terminal frames, ending with a four-second status summary;
- renders the frames with the system Swift/AppKit toolchain and removes temporary working data; and
- rejects output containing host identity, host paths, the real repository remote, common credential patterns, or a GIF of 5 MB or more.

The replay is entirely local. It does not start Claude Code, use an API key, or make a SaaS request.

All normal pre/post fixtures carry realistic `tool_use_id` correlation values. The generated evidence contains session start/end plus read, edit, command, and MCP actions. Tool post events display permission as `unknown`, because the Claude Code payloads do not explicitly report permission decisions.
