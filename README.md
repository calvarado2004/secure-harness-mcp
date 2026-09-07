# secure-harness-mcp

An MCP server for configuring and maintaining project-specific code checks.

Start by inspecting the repository and defining its security contract:
endpoints, access rules, protected resources and deployment assumptions.
Bind those requirements to readers and checks, and validate the checks before
using their results. After an acceptable MVP is established, check new additions
against that baseline. As the project evolves, review its requirements and
extend or correct the harness, then establish a new measured baseline.

This is not a tool for autonomous vulnerability prediction on unseen
repositories. Project-specific wiring and maintenance are part of the method.
[HISTORY.md](HISTORY.md) records reader, rule and integration corrections.

## Repository tools and research scope

| Tool | Function |
|---|---|
| `repo_inventory(repo, profile="")` | Reports runtime routing, configured lanes, unread/unclaimed files, suppressed rules and deployment context |
| `module_guidance(repo, path, profile="")` | Returns applicable rules, project facts, remedies, references and overreach notes for a module |

Supply `profile` explicitly or set `HARNESS_PROFILE`; the MCP tools reject
calls without a project profile. The existing profiles are examples for their
own subjects, not suitable defaults for another repository.

Inventory describes configured coverage; it does not execute every listed
analyzer or establish that a file is secure. A reported lane is not evidence
that the lane ran successfully on that file.

The accompanying paper uses these packs and tools alongside **study-specific
measurement services and repair controllers** in the paper's evidence tree.
The standalone pack server does not itself provide the complete experimental
build/test/attack battery, acceptance gate or rollback controller.
The older snippet tools and proxy below are separate interfaces, not substitutes
for that repository workflow.

The experimental gate protects recorded coordinates under fixed checks.
Finite checks and aggregate counts do not guarantee all behavior or authorize
release. Changes to policy, readers or deployment assumptions require review
and a new measured baseline.

## Install the repository MCP server

From a source checkout:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python packlib/mcp_server.py --selftest
.venv/bin/python -m packlib.packtest
.venv/bin/python -m packlib.selftest_packs
```

The repository tools need Python and the MCP/PyYAML dependencies. They do not
need Go or a model endpoint. Particular analyzer executions and controls may
have additional dependencies. Inspect both failures and skipped controls:
a skipped control is not a pass.

Launch the stdio server with:

```sh
HARNESS_PROFILE=your-project .venv/bin/python packlib/mcp_server.py
```

First create and validate `projects/your-project.yaml`; the example name
above is not a shipped profile. For an MCP client's server configuration,
use absolute paths:

```json
{
  "command": "/absolute/path/to/secure-harness-mcp/.venv/bin/python",
  "args": ["/absolute/path/to/secure-harness-mcp/packlib/mcp_server.py"],
  "env": {"HARNESS_PROFILE": "your-project"}
}
```

The same inventory and module guidance are available without MCP, from the
checkout root:

```sh
.venv/bin/python -m packlib.inspect_repo <profile> <repository>
.venv/bin/python -m packlib.inspect_repo <profile> <repository> <module-path>
```

The Homebrew formula is another installation path:

```sh
brew tap calvarado2004/secure-harness https://github.com/calvarado2004/secure-harness-mcp
brew install --HEAD secure-harness-mcp
```

It installs **three** commands: `secure-harness-packs` (repository MCP),
`secure-harness-mcp` (older snippet MCP) and `secure-harness-proxy`
(Python snippet proxy). The formula also installs Go for snippet build checks.
Use `secure-harness-packs` when configuring the repository tools.

## Policy packs

Packs separate rule ownership from runtime-specific readers and project facts:

```text
packs/<runtime>/<axis>/<tier>/pack.yaml
orgs/<organization>/pack.yaml
projects/<project>.yaml
```

Shared rule identifiers and severity definitions live under `packs/general/`.
Runtime packs bind applicable rules to detectors; project profiles supply facts
and select the relevant packs. New syntax or requirements may need new reader
or detector code, not just another YAML file.

The loader checks composition constraints, rejects held-out packs, and records
justified suppressions. `packtest` separately checks controls, documentation
and rule obligations; the runtime loader does not automatically execute that
test suite on every load. Suppression records are exposed to consumers, but
the paper's measured acceptance state does not include a suppression-count gate.

Readers exist for selected Python frameworks, browser JavaScript, Express,
compose, nginx, SQL seeding and configuration credentials. Several other
runtimes remain detect-only. Coverage depends on the selected profile and
available detectors; consult the inventory and per-pack limits.

See [packs/README.md](packs/README.md) for the current entry guide and
[docs/PACKS.md](docs/PACKS.md) for design details. Historical design statements
should be checked against `packlib/loader.py`, `packlib/packtest.py` and
the current detector implementation before relying on enforcement.

## Older snippet tools

`secure_coding_mcp.py` exposes `secure_generate`, `harden_code`,
`audit_code` and `score_code`. It uses `generate.py` for a bounded
generate/build/scan/repair loop. Its build check is Go-specific, and
`secure_generate` defaults to `language="go"`.

These tools can return code with residual findings after exhausting their
repair budget. They do not implement the paper's repository acceptance
contract or its project-specific functional checks.

Generation and repair require a configured model backend:

```sh
export SECURE_HARNESS_MODEL_URL=http://localhost:11434/v1
export SECURE_HARNESS_MODEL=your-served-model
export SECURE_HARNESS_KEY=your-endpoint-key
.venv/bin/python secure_coding_mcp.py
```

Use your endpoint's actual model identifier and supply credentials through the
local environment; do not commit credentials. Audit and scoring still depend
on the installed instruments. Model choice and tool availability can affect
results; the paper does not establish model equivalence.

## Older snippet proxy

The Python proxy processes a selected fenced Go/Python block in a
`/v1/chat/completions` response. It does not inspect every repository edit,
every language, or every code block. Responses without a recognized block
pass through. **On a harness exception, the Python handler returns the upstream
content with a passthrough note; it is not a fail-closed repository gate.**

```sh
secure-harness-proxy --port 8090
```

Configure `SECURE_PROXY_UPSTREAM`, `SECURE_PROXY_KEY` and
`SECURE_PROXY_MAX_ITERS` as described in [.env.example](.env.example).
Repair calls may incur model charges. Go/Python instrument requirements and
the Go proxy implementation are separate from the repository pack server.
Inspect the applicable implementation before treating any proxy as enforcement.

[docs/TECHNICAL.md](docs/TECHNICAL.md) retains the snippet-layer reference.
Its results and architecture should not be read as the current five-subject
repository experiment.

## License

MIT; see [LICENSE](LICENSE).
