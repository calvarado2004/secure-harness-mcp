# What this pack does NOT cover

- **It matches text, not scopes.** `localStorage.getItem('t')` in a dead code path counts as
  a read. A key written in one file and read in another is reported as half-wired, because
  the lane works per file.
- **`practice/unchecked-response` looks 400 characters ahead** of an `await fetch(`. A status
  check further away than that is missed; a check inside a wrapper the call delegates to is
  missed.
- **`practice/inconsistent-render-path` is a file-level heuristic.** A file that legitimately
  uses `innerHTML` for a static template and `textContent` for data is flagged. It is
  weighted MEDIUM for that reason.
- **It says nothing about correctness of the read path**, only about its existence.
