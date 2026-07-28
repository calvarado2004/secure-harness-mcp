# What this pack does NOT cover

- **It is a sink lane, not a taint engine.** It does not prove that attacker-controlled data
  reaches the sink. It reports that a sink is fed something not demonstrably inert.
- **It will miss an injection routed through a helper it cannot follow.** Markup assembled
  by a function in another file, then assigned, is only caught when the template literal
  itself carries markup.
- **It reads inline `<script>` and `.js` files as text.** There is no JS parser here, so a
  sink reached through a computed property (`el["inner"+"HTML"]`) is invisible.
- **Minified bundles are excluded by the runtime pack** (`*.min.js`, `*.bundle.js`). They are
  counted as unread in the inventory, not as clean.
- **`html/no-csp` checks the document only.** A CSP served as an HTTP header by the web
  server is the better practice and this lane cannot see it — expect a false positive on a
  correctly-configured deployment, and reweight rather than suppress.
- **It is browser-shaped.** A `.js` file that runs under Node has entirely different sinks
  (`child_process`, `fs`, `vm`) and none of them are here. That is a separate runtime
  (`node-js`), not a gap in this one — see `packs/README.md`.
