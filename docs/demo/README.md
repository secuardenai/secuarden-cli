# Current CLI walkthrough

The GIF shows actual output from the current checkout, using **synthetic Claude
Code hook payloads**. It is a reproducible product walkthrough, not a recording
of a live agent session. No agent, model API, or Secuarden SaaS is called.

## Regenerate

On macOS, with Go 1.25+, Python 3, Git, and Swift/AppKit installed:

```bash
./docs/demo/generate.sh
```

The generator builds this checkout, creates a unique disposable home and Git
repository, and uses a synthetic developer identity. Only child processes receive
the isolated environment; your agent configuration and capture database are not
modified. Go dependency downloads may be needed on a cold cache.

The walkthrough shows:

1. Current `init --repo .` setup with repository scope and explicit receipt mode.
2. A read, sensitive-path read, edit, reported failing command, and MCP call,
   including matching pre/post hook payloads.
3. Recent events and a filtered sensitive-access investigation.
4. A repository-scoped accountability report.
5. Successful verification of the stored hash chain.

The generator also parses an AI-BOM export and checks integrity JSON. It fails on
command errors, identity leakage in display output, oversized GIFs, or vertically
clipped frames. The setup screen is explicitly excerpted; its full output is in the transcript.
Other long output is wrapped and paginated instead of silently omitted.
Temporary paths are abbreviated to `/demo/repository` and `/demo/home` for display;
stored records remain unmodified. The fixture's reported test failure is simulated,
not the result of running an application test suite.

`transcript.txt` is the accessible text companion. `preview-*.png` files are local
visual-review outputs and need not be committed. Each screen remains visible for
seven seconds; the final verification screen remains for five seconds.

## Recording a genuinely live replacement

Use a disposable Git repository containing only demonstration code and placeholder
data, with a supported, authenticated agent. Build and install this checkout to a
stable binary path first. In that repository:

```bash
secuarden init --repo . --agent claude-code --scope repo --receipt-mode explicit
```

This changes the current OS user's Claude hooks and Secuarden capture scope. Use a
dedicated demo OS account if you need to preserve your everyday capture setup.
Start a fresh Claude Code session and ask it to read the demo code, make one small
change, and run the actual tests. Then record these commands:

```bash
secuarden events --last 8
secuarden events --sensitive --last 4
secuarden report --since 24h --limit 2
secuarden verify
```

Use `docs/live-capture-verification.md` to establish runtime delivery separately.
Review all visible paths, identities, commands, and file contents before publishing.
Only label the replacement as live after it is recorded from that real session;
this fixture generator must retain its replay label.
