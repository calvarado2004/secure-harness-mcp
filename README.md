# secure-harness-mcp

**A verify-and-repair secure-coding harness, exposed as an MCP server (and a transparent proxy).**

Consumer / self-hosted LLMs write code with the security posture of their training data — which is to
say, insecurely by default, and often *plausibly* wrong: code that looks fine and isn't. This project
wraps any OpenAI-compatible model in a **verify-and-repair loop** — generate, then *build and
security-scan the result*, feed every compiler error and finding back, and regenerate — so the model
cannot ship code that fails to compile or trips a detector without you knowing.

It is the operational form of a simple research result: **how you wrap the model (the harness)
determines output security far more than which model you pick, and a secure-coding *prompt alone* is a
trap — only the feedback loop delivers both security and buildability.**

> **Scope.** This project has two layers, and the research uses the second. The **snippet** layer
> (`secure_generate`, `harden_code`, `audit_code`, `score_code`) generates and hardens code in
> isolation; its build check is Go-specific and `secure_generate` still defaults to `language="go"`.
> The **repository** layer — policy packs plus `repo_inventory` / `module_guidance` — reads a project
> that already exists against the policy that project declares, and it is what the accompanying paper
> measures across five subjects in Python and TypeScript. If you came from the paper, the packs are
> what you want; the snippet tools are older and neither necessary nor used for any result in it.

> ⚠️ **A strong filter, not a proof.** The harness removes what its instruments can see (build errors,
> pattern detectors, `bandit`) and reports honest residuals for the rest. It does not guarantee
> security — static analysis still misses classes such as argument injection. Treat its output as
> *hardened and checked*, not *certified*.

---

## What it gives you

**Repository tools** — the layer the research uses. These read a project you already have, against
the policy it declares:

| tool | what it does |
|---|---|
| `repo_inventory(path)` | inventory a repository by runtime, naming what has a lane and what is **unread** rather than clean |
| `module_guidance(path)` | the rules that apply to a given module, routed by its runtime and the project's profile |

**Snippet tools** — the older surface, for generating and hardening code in isolation:

| tool | what it does |
|---|---|
| `secure_generate(spec, language=…)` | write new code for a spec, guided prompt **+ build/scan repair loop**; returns vetted code |
| `harden_code(code)` | take existing code, fix its weaknesses, return a **before/after** comparison |
| `audit_code(code)` | run the pattern detectors (+ CWE + rationale) — candidates, not verdicts |
| `score_code(code)` | build/robustness + findings scorecard for a snippet |

**A transparent proxy** (`secure-harness-proxy`, shipped in two implementations, Go and Python): an
OpenAI-compatible endpoint that fronts any model; every completion containing code is run through the
loop automatically, so *any* client pointed at it is hardened with no client change.

## Policy packs: the rule set as an editable, testable artifact

The tools above ship a fixed rule set. **Packs** make the rules an artifact you own — organised
per programming language, then axis, with a company layer on top — so a team can encode its own
security practices, engineering standards and internal conventions without forking anything.

```
packs/<runtime>/<axis>/<tier>/pack.yaml
       │         │      └── who owns it:  commodity < framework < org < project
       │         └───────── what the gate promises:  security, authorization, practice
       └─────────────────── which parser can open the file:  python, browser-js, sql, ...
```

`packs/general/` holds what belongs to no language — the one severity scale, the word lists that
mean the same thing everywhere, and cross-language rules that each language pack *binds* to its own
detector, so one invariant keeps one id and one weight across a polyglot repository.

The two repository tools above are how an agent in an unfamiliar repository asks the packs a
question — `repo_inventory(repo, profile)` routes every file to the packs that read it and reports
what **nothing** reads; `module_guidance(repo, path, profile)` returns the rules that apply to *this*
module because of its language, plus the project's declared facts and deployment context.

Run it standalone:

```bash
python -m packlib.mcp_server          # MCP over stdio
python -m packlib.inspect_repo <profile> <repo>    # same thing, as a CLI
python -m packlib.packtest            # do the packs discharge their obligations?
python -m packlib.selftest_packs      # does the pack system itself still hold?
```

```jsonc
// MCP client config — absolute path, so no working directory has to be set
{
  "command": "/path/to/venv/bin/python",
  "args": ["/path/to/secure-harness-mcp/packlib/mcp_server.py"],
  "env": { "HARNESS_PROFILE": "your-project" }
}
```

Verify the install before wiring it into a client — it exits non-zero if anything is missing:

```bash
pip install -r requirements.txt
python packlib/mcp_server.py --selftest     # server builds, both tools register
python -m packlib.packtest                  # every pack discharges its obligations
python -m packlib.selftest_packs            # the pack system itself still holds
```

Works with both `mcp` 1.x and 2.x — they moved the server class between majors, and
`make_server()` shims it.

### What makes this different from a linter config

- **A blind spot is reported, never skipped.** Files a runtime claims but no lane reads come back
  as UNREAD; files no runtime claims come back as UNCLAIMED. Neither is a clean result. Running
  this against its own development subject immediately surfaced two: the container files and the
  SQL seed script that grants privileges and inserts the first administrator.
- **A company layer may not weaken the policy silently.** An overlay can add, reweight, supply
  facts, or suppress — but suppression requires a written justification *and* a paired negative
  control on disk, and the suppressed rule stays visible in the resolved state instead of
  disappearing. Deleting or redefining a rule owned by a higher tier is refused outright.
- **A rule can ship a known-good reference.** Prose tells a model what is wrong; a reference
  shows it what right looks like. `seed/default-admin-credential` carries three concrete
  mechanisms for seeding a database without shipping a credential, and the MCP hands the
  whole document to the model alongside the finding.
- **Every rule states its overreach.** Not just "what attack does this stop?" but "what does a
  *too-strict* application of it break in a real deployment?" Least privilege is the goal and a
  real stack still has to connect to things; a rule that breaks a working deployment gets switched
  off, taking the protection it did provide with it. "None known" is a legitimate answer — silence
  is not.
- **Deployment context reprices findings.** Binding `0.0.0.0` is correct for a container on an
  internal network behind a proxy and a real defect on a host. A project declares its deployment
  and rules are priced against it, with the reason recorded — change the deployment and the finding
  comes back at full weight.
- **Packs must earn admission.** `packtest` enforces seven obligations (positive control, paired
  negative control, an "I could not measure this" verdict, stated limits, attack-or-failure per
  rule, held-out isolation, and overreach) and refuses to load a pack that fails one.

Languages today: `python` and `browser-js` have lanes. `container`, `sql`, `node-js`, `shell`,
`go`, `java`, `c` and `cpp` are **detect-only** — declared, so their files are inventoried as
unread rather than silently ignored, which is a legitimate state to ship and an honest one.

Full documentation: **[docs/PACKS.md](docs/PACKS.md)**.

---

## Architecture

Two entry points — the **MCP server** (explicit tools) and the **transparent proxy** (implicit, on
every completion) — share one **verify-and-repair core** (`generate.py`), which drives a model backend
and gates its output on **self-tested instruments** before returning it.

```mermaid
flowchart TD
    C1["Qwen Code"] -->|stdio MCP| MCP
    C2["Claude Code"] -->|stdio MCP| MCP
    C3["Cursor / any MCP client"] -->|stdio MCP| MCP
    C4["curl / editor / any agent"] -->|HTTP /v1| PROXY

    MCP["MCP server — secure_coding_mcp.py<br/>tools: secure_generate · harden_code · audit_code · score_code"]
    PROXY["Transparent proxy — secure_proxy.py<br/>OpenAI-compatible /v1 · hardens every code block"]

    MCP --> GEN
    PROXY --> GEN

    subgraph loop["Verify-and-repair core · generate.py"]
        direction TB
        GEN["generate · model_chat"] --> EXT["extract code block"]
        EXT --> SCAN["build + scan"]
        SCAN --> DEC{"builds clean<br/>and no findings?"}
        DEC -->|"no — feed each error / finding back (≤ N iters)"| GEN
    end

    DEC -->|yes / fast path| OUT["hardened code<br/>+ honest residual note"]
    OUT -.->|returned to caller| C4

    GEN <-->|OpenAI API| BE["Model backend<br/>vLLM · Ollama · llama.cpp · hosted<br/>SECURE_HARNESS_MODEL_URL"]

    subgraph instr["Self-tested instruments (snippet layer) — +/- controls, documented FP quarantine"]
        direction TB
        I1["go build / go vet"]
        I2["gosec"]
        I3["bandit — advisory subprocess FPs quarantined; shell=True still blocks"]
        I4["pattern detectors · vuln_patterns.yaml"]
    end

    SCAN --> I1
    SCAN --> I2
    SCAN --> I3
    SCAN --> I4

    AUD["scan_repo.py — shard + refute repo audit"] --> I4
```

**How to read it.** A request enters through either the MCP tools or the proxy and lands in the same
loop: generate → extract → *build and scan* → if the code fails to compile or trips a detector, feed
the specific errors and findings back and regenerate (up to `N` iterations); otherwise return it with
an honest residual note. Code that is already clean takes the **fast path** — zero extra model calls,
so cost is proportional to risk. Every gate is a **self-tested instrument**: a known-insecure snippet
must score worse than its secure twin and a broken snippet must fail to build, so a reported "0
findings" means *the instrument looked and found nothing*. `scan_repo.py` reuses the same pattern
detectors to audit an existing repository.

## How the loop works

```
 spec ─▶ generate (model) ─▶ build + scan (self-tested) ─▶ clean & builds? ──yes──▶ return
                    ▲                                              │
                    └──────────── feed each error/finding back ◀───no  (≤ N iters)
```

Every instrument is **self-tested**: a known-insecure snippet must score worse than a secure one, and
a broken snippet must fail to build — so a reported "0 findings" means *the instrument looked and found
nothing*, not that it was misconfigured. Known false-positive classes (e.g. `bandit`'s advisory-only
subprocess notices, or Go's secure `exec.Command(bin, args...)` form) are quarantined and documented,
while genuine injection (`shell=True`) stays blocking.

---

## Requirements

- **Python 3.10+** with `mcp`, `PyYAML` (and `bandit` for the Python proxy path).
- **Go** on `PATH` — *optional, and only for the snippet tools*: it is what compiles generated Go in
  the build check, and it enables `golang.org/x/crypto` so secure choices like `bcrypt` build. The
  repository tools and the policy packs do not need it.
- An **OpenAI-compatible model endpoint** (local vLLM / llama.cpp / Ollama, or a hosted API).

## Install

### Homebrew (recommended)

```bash
brew tap calvarado2004/secure-harness https://github.com/calvarado2004/secure-harness-mcp
brew install --HEAD secure-harness-mcp
```

This installs two commands: `secure-harness-mcp` (the MCP server) and `secure-harness-proxy` (the
transparent proxy), each in its own virtualenv, with `go` and `python@3.12` as dependencies.

*(Or, from a clone: `brew install --HEAD ./Formula/secure-harness-mcp.rb`.)*

### From source

```bash
git clone https://github.com/calvarado2004/secure-harness-mcp
cd secure-harness-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python secure_coding_mcp.py   # stdio MCP server
```

## Configure the model backend

The harness hardens the output of whatever model you point it at (model choice barely matters — that's
the thesis). Set three env vars (copy `.env.example`):

```bash
export SECURE_HARNESS_MODEL_URL=http://localhost:11434/v1   # any OpenAI-compatible endpoint
export SECURE_HARNESS_MODEL=qwen2.5-coder:32b               # the served model id
export SECURE_HARNESS_KEY=dummy                             # API key if the endpoint needs one
```

---

## Add the MCP to your tools

### Qwen Code

One-liner:

```bash
qwen mcp add secure-coding secure-harness-mcp
```

Or add it to `~/.qwen/settings.json` under `mcpServers` (use the from-source path if not installed via
Homebrew):

```json
{
  "mcpServers": {
    "secure-coding": {
      "command": "secure-harness-mcp",
      "env": {
        "SECURE_HARNESS_MODEL_URL": "http://localhost:11434/v1",
        "SECURE_HARNESS_MODEL": "qwen2.5-coder:32b",
        "SECURE_HARNESS_KEY": "dummy"
      },
      "description": "Verify-and-repair secure-coding harness"
    }
  }
}
```

Verify it connected, then use it (headless runs need `-y` to auto-approve tool calls):

```bash
qwen mcp list          # → secure-coding ... Connected
qwen -y -p "Use secure_generate to write a Go HTTP handler that returns a file from ./data by name.
            Report builds and findings."
```

### Claude Code

```bash
claude mcp add secure-coding \
  -e SECURE_HARNESS_MODEL_URL=http://localhost:11434/v1 \
  -e SECURE_HARNESS_MODEL=qwen2.5-coder:32b \
  -- secure-harness-mcp
```

### Cursor / any MCP client

Add to the client's `mcp.json`:

```json
{
  "mcpServers": {
    "secure-coding": {
      "command": "secure-harness-mcp",
      "env": {
        "SECURE_HARNESS_MODEL_URL": "http://localhost:11434/v1",
        "SECURE_HARNESS_MODEL": "qwen2.5-coder:32b"
      }
    }
  }
}
```

*If you installed from source instead of Homebrew, replace `"command": "secure-harness-mcp"` with
`"command": "/absolute/path/to/.venv/bin/python"` and `"args": ["/absolute/path/to/secure_coding_mcp.py"]`.*

---

## Bonus: the transparent proxy (harden *any* client automatically)

Instead of calling a tool, front your model with the loop so **every** request is hardened — no client
change, the model can't opt out:

```bash
# run it directly
secure-harness-proxy --port 8090        # env: SECURE_PROXY_UPSTREAM / SECURE_PROXY_KEY / SECURE_PROXY_MAX_ITERS

# or always-on via Docker (toolchain baked in)
cp .env.example .env    # set SECURE_PROXY_UPSTREAM
docker compose up -d    # -> http://localhost:8090/v1
```

Then point any OpenAI-compatible client (Qwen Code, Cursor, `curl`) at `http://localhost:8090/v1`.
Code that already builds clean passes through with **zero** extra model calls (cost is proportional to
risk); risky code is repaired and returned with an honest residual note.

## Recursive by design

An agent that writes code can call `harden_code` on its *own* output before returning it — the research
result as a runtime safety layer.

## Deep dive

See [`docs/TECHNICAL.md`](docs/TECHNICAL.md) for the full technical reference: the repair algorithm,
every instrument and detector, the self-tests and false-positive quarantine, the MCP/proxy API
surfaces, configuration, the measured findings, and an honest limitations section.

## Honest caveats

- **Filter, not proof** — it removes what the instruments detect; static analysis misses some classes.
- **Some weaknesses resist the loop** — e.g. code that needs restructuring rather than a local fix; the
  residual note says so plainly.
- **Needs the toolchain** — for the snippet layer, without `go`/`bandit` present the loop degrades to
  prompt-only (a trap); the Docker image bakes them in so this can't happen silently. The repository
  layer needs neither.
- **Cost** — each risky generation costs 1 + up-to-N repair passes; well spent when quality matters.

## License

MIT — see [LICENSE](LICENSE).
