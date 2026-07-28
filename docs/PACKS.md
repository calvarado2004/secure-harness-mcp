# Packs: the rule set, as an artifact you can read, edit and test

A pack is one cell of a grid, and the directory layout is the grid:

```
packs/<runtime>/<axis>/<tier>/pack.yaml
       │         │      └── who owns it:  commodity < framework < org < project
       │         └───────── what the gate promises:  security, authorization, practice
       └─────────────────── which parser can open the file:  python, browser-js, sql ...
```

plus `packs/general/`, which holds what belongs to no language: the one severity scale, the
word lists that mean the same thing everywhere (`secret`, `is_admin`, `token`), and
cross-language rules that each language pack *binds* to its own detector.

## Why it is shaped this way

Before this, `repo_authz.py` held four different owners' knowledge in one file: how FastAPI
expresses a route (true of every FastAPI project), which dependency establishes identity
here (true of one company), which routes are public on purpose and which models are
sensitive (true of one application), and a generic privilege vocabulary. Changing any one of
them meant editing Python. Adding a language meant editing Python. A company with its own
standards had nowhere to put them but a fork.

Three properties follow from the split, and they are the reason it was worth doing:

- **Extensible.** A new language is a directory. A new company standard is an overlay file.
- **Testable.** Every pack ships its own controls and must pass `packtest` to load at all.
- **Legible.** You can point at the line that caused any verdict, including "why was this
  HIGH downgraded to LOW?" — `explain()` prints the history.

## The five-minute tour

```bash
cd evidence

# what would the harness read here, and what can nothing read?
python -m packlib.inspect_repo dealership car_dealership-experiment/car_dealership_original_code

# which rules apply to ONE module, because of the language it is in?
python -m packlib.inspect_repo dealership <repo> frontend/index.html

# do all the packs discharge their obligations?
python -m packlib.packtest

# does the pack system itself still hold?  (equivalence + merge semantics + routing)
python -m packlib.selftest_packs
```

## What a layer may do

| operation | who | rule |
|---|---|---|
| **add** a rule | any tier | must state its attack (security) or its prevented failure (practice), *and* its overreach |
| **bind** a detector to a rule | language packs | the rule must already be declared; keeps one id and one weight across languages |
| **reweight** | org, project | only onto the shared severity scale; recorded in the rule's history |
| **supply facts** | org, project | answers a `requires_facts` a higher pack declared it needs |
| **context reweight** | any | against `deployment:` — and `why` is mandatory |
| **suppress** | org, project | **only** with a justification *and* a paired negative control on disk |
| **delete / redefine** a higher tier's rule | nobody | the loader refuses, loudly |

A suppressed rule **does not disappear.** It moves to `resolved.suppressed`, which is carried
into the run state next to `(w, r, v, m)` so the gate can refuse any candidate that raises
it. Without that, an overlay would be a legal way to shrink the search space while every
total still trended down — which is the failure this whole project documents.

## What every pack owes you (`packtest` enforces all seven)

1. **A positive control** — a deliberately defective artifact every rule must flag. Without
   it you cannot tell "this codebase is clean" from "my rule is broken."
2. **A paired negative control** — for every false-positive filter, a real defect it must
   still catch. Writing the browser lane, these caught two rule bugs in minutes, one of
   which was double-counting every finding (load 91 where the truth was 43).
3. **An unmeasured verdict** — how the pack says "I could not read this," distinct from
   "clean." Every AST engine returns zero on a file that does not parse.
4. **Stated limits** — a non-empty `LIMITS.md`. A bespoke lane whose limits are undocumented
   will be read as a complete one.
5. **Attack or failure, per rule** — security rules state the attack; practice rules state
   the failure prevented. A rule that states neither must not carry weight.
6. **Held-out isolation** — a pack marked `heldout: true` is refused by the loader, so
   Semgrep's independence is mechanical rather than conventional.
7. **Overreach, per security rule** — *what does a too-strict application of this break?*
   Security wants everything closed and least privilege is the right instinct, but a real
   stack has to connect to things. A rule that cannot say what over-applying it costs gets
   applied where it does not belong, breaks a working deployment, and is switched off —
   taking the attack it *did* stop with it. "None known" is a legitimate answer; silence is
   not, because silence is indistinguishable from never having asked.

## The rule that came out of reviewing this system

**Every value copied out of code into a pack gets an equality control, or it is not
configuration — it is a second source of truth waiting to drift.** Four values were
duplicated into pack files during the build with nothing checking them, and one had
*already* diverged: the browser `inert` regex, written as a readable multi-line block
scalar, carried newlines the compiled pattern does not. The pack documented a different
regex than the lane ran, and no total anywhere would have shown it. `selftest_packs` now
asserts character-for-character equality for every one of them.

Two more found in the same pass, both fixed with controls:

- `for_runtime` returned cross-language rules to every language, so a Python module would
  have been advised about `localStorage`. A rule declared in `general/` now reaches only the
  runtimes that actually **bind** it. Advice for the wrong language is worse than none — it
  is how a practitioner learns to stop reading the output.
- `fp_rules` was declared in a pack and read by nobody. Data that looks like configuration
  and configures nothing is worse than absent data, because a reader will believe it.

## Adding a language

1. `packs/<runtime>/pack.yaml` with a `detect:` block and an `unmeasured_verdict`. Stop
   here and you have a **detect-only** runtime: its files are inventoried as UNREAD rather
   than silently ignored. That is a legitimate state to ship — `c`, `cpp`, `go`, `java`,
   `shell`, `sql`, `node-js` and `container` are all in it today.
2. `packs/<runtime>/<axis>/commodity/` with rules, controls and `LIMITS.md`.
3. `python -m packlib.packtest <runtime>` until it is green.
4. Bind any cross-language rule from `general/practice` rather than inventing a second id
   for the same invariant.

## Runtimes today

| runtime | status | note |
|---|---|---|
| `python` | lanes: bandit, codeql, credential-logging, authz (FastAPI), practice | |
| `browser-js` | lanes: frontend sinks, practice | the blind spot that motivated all of this |
| `container` | detect-only | Dockerfile / compose / k8s. Also supplies `deployment:` context that reprices other packs' findings |
| `sql` | detect-only | found by the inventory, not by design: `init-db.sql` was claimed by nothing |
| `node-js` | detect-only | same extensions as the browser, different sinks — the profile breaks the tie |
| `shell`, `go`, `java`, `c`, `cpp` | detect-only | |

## Files

- `packlib/loader.py` — composition and the tier contract
- `packlib/detect.py` — file → runtime routing, and the blind-spot inventory
- `packlib/packtest.py` — the seven obligations
- `packlib/selftest_packs.py` — equivalence with the pre-pack code, merge semantics, routing
- `packlib/inspect_repo.py` — CLI, and the backing for the `repo_inventory` /
  `module_guidance` MCP tools
- `projects/*.yaml` — one file per subject: facts, deployment, spec
- `orgs/*/pack.yaml` — company overlays (`acme` is a worked example)
