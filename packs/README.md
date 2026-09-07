# Policy packs: project requirements, bindings and controls

Packs contain requirements a team wires into its project's coding workflow.
Inspect the repository, declare the relevant security and quality rules,
implement or select their checks, and validate them before establishing an
acceptable MVP. Check subsequent additions against that baseline. Periodic
project review may require new rules, readers and a new measured baseline.

A fixed pack set cannot cover requirements it has never encoded. This
infrastructure supports project configuration and extension, not autonomous
discovery on unseen repositories.

## Layout and ownership

```text
packs/<runtime>/<axis>/<tier>/pack.yaml
orgs/<organization>/pack.yaml
projects/<project>.yaml
```

Shared severity definitions, vocabulary and cross-language rule identifiers
live under `packs/general/`. Runtime packs bind rules to detector
implementations. Profiles select packs and supply project facts such as
public routes, identity guards and deployment assumptions.

A new language starts with a runtime descriptor, but useful analysis also
requires readers, detectors and controls. A new project requirement may need
implementation work as well as YAML configuration.

| Operation | Composition constraint |
|---|---|
| Add a rule | State the attack or prevented failure and the applicable overreach |
| Bind a detector | Reference an existing rule identifier |
| Reweight | Use the shared severity scale; record the change |
| Supply facts | Provide the declared project or organization facts |
| Context reweight | Give a reason; unverified deployment claims leave reweights deferred |
| Suppress | Supply a justification and a paired control file |
| Redefine a higher-tier rule | Rejected by the loader |

Suppressions remain in `resolved.suppressed` and in inventory/guidance
responses. **Visibility is not enforcement:** the paper's recorded acceptance
state does not include a suppression-count coordinate. A consumer that wants
to prohibit policy changes must protect or validate the policy itself.

## Run the checks

Use the directory containing `packlib/` as the working directory:
`evidence/` in the paper checkout, or the standalone harness checkout root.
Install the required dependencies first.

```sh
python3 -m packlib.inspect_repo <profile> <repository>
python3 -m packlib.inspect_repo <profile> <repository> <module-path>
python3 -m packlib.packtest
python3 -m packlib.selftest_packs
```

The inventory reports configured lanes, unread runtimes and unclaimed files.
It does not execute all analyzers. Inspect the actual scan's measurement status;
a configured lane is not proof of successful execution or complete coverage.

`packtest` is a separate validation command. The loader checks composition
and isolation constraints but does **not** run the entire control suite on each
load. Missing detector dependencies can produce skipped controls; review the
skip count as well as the exit status.

## Validation obligations

Packs declare positive and paired negative controls, a distinct unmeasured
verdict, limits, each rule's attack or prevented failure, held-out status and
security-rule overreach. `packtest` checks these obligations where supported.

A parse failure must not be read as a clean scan. A rule's declared
unmeasured verdict and its implemented error handling both need validation.
Finite paired controls exercise selected cases; they do not prove complete
coverage or the absence of false positives.

The loader refuses a pack marked `heldout: true`. This prevents that pack
from entering a resolved policy, but does not by itself prove independence
of every historical experiment. Which analyzer supplied repair feedback must
be established from the campaign's records.

`selftest_packs` checks merge semantics, routing and duplicated constants.
Its equality controls were added after a YAML regex diverged from the
implemented pattern. See the paper's harness-history report or the standalone
harness's `HISTORY.md` for the maintenance record.

## Available readers and remaining gaps

Coverage is profile-dependent; the following lists implemented pack families,
not a promise to analyze every file in those languages.

| Runtime | Available checks or status |
|---|---|
| Python | Static/practice checks; FastAPI, Flask, flask-restx and flask-restful authorization bindings; seed and object-store checks |
| Browser JavaScript | Selected frontend sinks and practice checks |
| Node JavaScript/TypeScript | Express authorization binding; other frameworks are not implied |
| Container configuration | Compose checks; this is not full Dockerfile/Kubernetes analysis |
| SQL | Seed checks |
| nginx | Selected edge-configuration checks |
| Configuration files | Committed credential checks |
| Swift, shell, Go, Java, C, C++ | Detect-only in the pack system |

A runtime descriptor can still say detect-only while an optional framework
pack supplies a lane. The resolved profile and inventory determine the
selected coverage; the descriptor alone is not the final coverage report.

## Extending the packs

1. Declare runtime detection and how unread input is reported.
2. Implement or bind the needed reader and detector; record limits.
3. Add controls for the defect, intended valid behavior and unavailable input.
4. Load the project profile and inspect routing and deferred reweights.
5. Run `packtest` and `selftest_packs`, then validate the project-level
   measurements and establish the baseline.

The implementation is in `packlib/loader.py`, `detect.py`,
`packtest.py`, `selftest_packs.py` and `inspect_repo.py`.
The standalone MCP entry point is `packlib/mcp_server.py`.
