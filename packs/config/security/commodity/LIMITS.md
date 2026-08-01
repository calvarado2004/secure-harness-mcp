# What this pack does NOT cover

- **It reads `.env`-shaped files only.** A credential in `config.json`, `settings.yaml`, a
  Kubernetes manifest, a CI variable or a shell profile is not read here. Those live in
  runtimes that have their own packs, and the container and seed lanes already cover two of
  them; the rest are a declared gap.
- **"Real" versus "placeholder" is a pattern match** against a vocabulary of the usual
  documentation words. A project whose placeholder convention is not in that vocabulary will
  be reported, and a real secret that happens to read like a placeholder will not. The rule
  errs toward silence on the second, which is the direction that loses findings.
- **Committed-ness is answered by git where there is a git checkout, and by `.gitignore`
  otherwise.** In an extracted tarball with no ignore file the lane assumes the file would be
  committed, which over-reports rather than under-reports.
- **It cannot tell whether a disclosed value is still live.** The remedy says rotate, because
  the lane has no way to check and the safe assumption is that anything pushed is public.
- **It says nothing about history.** A file untracked today may still sit in an earlier
  commit, and this lane reads the working tree only.
