# What this pack does NOT cover

- **It reads configuration; it does not interpret nginx.** `if`, `map`, variable
  interpolation, regex location precedence and `include`d files it was not handed are all
  invisible to it. A location protected by a mechanism it cannot see will be reported.
- **It does not prove reachability.** A `location` block in a `server` that never matches
  the request's `Host` is still reported.
- **"The application upstream" is inferred as the most frequent `proxy_pass` host.** In a
  config that proxies to several services evenly, that inference is arbitrary and
  `nginx/proxies-backing-service` may name the wrong one — or stay silent.
- **It says nothing about TLS, headers, rate limits or request size.** Those are real, and
  every rule this lane could add for them failed the "can you state the attack?" test at the
  weight it would have carried.
- **A third rule was written and deliberately not shipped.**
  `nginx/undeclared-public-path` flagged any location outside the project's declared public
  routes. On the real subject it fired seven times, all on paths the application
  authenticates itself, with no attack to state and a suppression as the only realistic
  response. It is documented in the lane source so nobody re-adds it without reading why.
