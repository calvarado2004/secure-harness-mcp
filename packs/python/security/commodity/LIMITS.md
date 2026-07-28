# What this pack does NOT cover

- **It reports what its engines report.** bandit is a pattern scanner: it sees shapes, not
  data flow. CodeQL sees flow but only for the queries in the suite named in `lanes:`. A
  defect class in neither is not covered, and its absence from the total says nothing.
- **`sev: engine` means the engine decides.** This pack does not second-guess a severity
  except through `reweight:` in an overlay or `context_reweight:` against the deployment.
- **The dataflow rules (`py/*`) need a whole application.** They cannot be demonstrated on a
  single control file, so the positive control here proves only that bandit ran — see the
  file's own docstring. That is a narrower claim than "these rules work", deliberately.
- **False-positive filters are pattern-based and will over-suppress somewhere.** Each one is
  paired with a negative control, which bounds the damage but does not eliminate it. The
  known trades are in `controls/negative/safe.py`.
- **It is not a taint engine for the application's own helpers.** A value laundered through
  a project-specific sanitiser is invisible to it — and a sanitiser that does not actually
  sanitise (observed in this project: a log wrapper that still logged the credential) reads
  as a fix.
- **Nothing here knows about authorization.** "Is this endpoint allowed to do that?" has no
  answer in this pack; that is the authorization axis, and on the brownfield subject these
  commodity lanes reported exactly one finding — a false positive — on an application
  serving its entire customer table anonymously.
