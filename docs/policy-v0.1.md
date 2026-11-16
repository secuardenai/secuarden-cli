    # Local decorator enforcement v0.1

Import a JSON policy to activate protection on the next synchronous pre-tool
hook. No SaaS connection or daemon restart is needed. Policies are user-wide,
stored at `~/.secuarden/policies.json`, and apply across repositories regardless
of capture scope. This release supports Python route security decorators.

## Build and configure for a Codex Flask demo

Run these commands yourself in a terminal, before starting the demo session:

```sh
make build
# Use the absolute path to this newly built binary throughout the test.
/absolute/path/to/secuarden-cli/bin/secuarden init --repo /path/to/flask-demo --agent codex --enable-codex-hooks
/absolute/path/to/secuarden-cli/bin/secuarden policy upload --file /absolute/path/to/secuarden-cli/fixtures/policy/flask-security.json
/absolute/path/to/secuarden-cli/bin/secuarden policy list
```

`init` installs hooks pointing at that binary. Start a fresh Codex session after
installing hooks. Codex must support and enable synchronous hooks and trust the
project/hooks; installing the CLI alone is insufficient. Existing sessions with
current synchronous hooks see imported policies on the next tool invocation.
`python3` >= 3.8 must be on the hook process PATH. It parses source with `ast` in
isolated mode; project code is never imported or executed.

The example protects `login_required`, `fresh_login_required`, `roles_required`,
`roles_accepted`, `jwt_required`, and `auth_required`. Keep names your app uses
and add custom decorators before importing. Bare names match the last component
of a dotted name; dotted names match exactly. Explicit import aliases are
resolved. Route decorators include Flask/Blueprint `route`, `get`, `post`,
`put`, `patch`, `delete`, `options`, and `head`.

Prepare this route in the demo repository **before** importing the policy:

```python
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route('/private')
@login_required
def private():
    return 'hello'
```

Ask Codex: “Use apply_patch to remove @login_required from app.py.” Expect a
tool denial naming `protect-flask-route-security`; verify in your terminal that
the file is unchanged. Also try changing decorator arguments, commenting out
the decorator, reordering the stack, moving it to another function, deleting
the route, or deleting its file. These should be denied.

For the positive control, ask: “Use apply_patch to change only the return value
from hello to world.” This should succeed. A formatting-only change that leaves
the Python AST unchanged is permitted.

## Contract and behavior

See [the importable bundle](../fixtures/policy/flask-security.json) for the exact
JSON format. `version` must be `0.1`. Each entry requires `id`,
`kind: protect_route_security_decorators`, `language: python`, nonempty
`security_decorators`, and nonempty `route_decorators`. Unknown fields and
unsupported capabilities are rejected. IDs are unique. Malformed JSON or an
invalid envelope rejects the whole upload; invalid entries are skipped with
reasons while valid entries activate. Existing IDs are skipped, never silently
overwritten. If nothing imports, the command exits unsuccessfully.

Activation uses a locked, atomic store update. The upload prints counts and the
resulting local policy list. A corrupt/unreadable store denies tool calls;
an absent store preserves passive capture behavior.

The engine compares the before/after AST of `.py` files. For functions carrying
both a configured route decorator and a configured security decorator, it
preserves the full decorator stack, arguments, ordering, function identity, and
resolved decorator imports. Adding a protected stack also changes that snapshot
and is denied. Route-body edits remain possible.

Supported mutation inputs are `Edit`, `Write`, `MultiEdit`, and exact-context
Codex `apply_patch` (string input or an object containing `command`, `input`, or
`patch`). Evaluation never writes source. Invalid Python, unreadable/oversized
files, parser failures, ambiguous patches, and rename patches are denied.
Files and hook inputs are limited to 2 MiB; Python evaluation shares a two-second
deadline across a tool call. Denials use the existing agent pre-tool/permission
response protocol and precede passive capture; denied proposals currently do
not enter the capture database.

## v0.1 boundaries

Shell commands and unsupported tools are denied while any policy is active,
including shell-based reads/tests. The engine cannot predict arbitrary shell
side effects. Use your own terminal for tests and inspection, and supported
file tools for agent edits. This is intentionally restrictive for the first
end-to-end experiment.

This protects decorator syntax on hooked file operations. It is not an OS
sandbox or proof that authentication works: direct human edits, disabled hooks,
other processes, concurrent external writes, dynamic route registration,
decorator implementation changes, runtime rebinding, and control-flow changes
are outside this version. Source with syntax newer than the installed Python
parser is denied. General data-flow analysis and tamper-resistant enforcement
are not provided.

To reset after the demo, run this yourself in a terminal (this disables **all**
imported policies while retaining a backup):

```sh
mv ~/.secuarden/policies.json ~/.secuarden/policies.json.disabled
```

Then edit the example bundle and import again. Removal/update commands,
repository-scoped policy management, richer tool coverage, and SaaS delivery
are deferred.
