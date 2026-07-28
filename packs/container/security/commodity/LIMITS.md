# What this pack does NOT cover

- **It reads one compose file.** `extends`, multiple `-f` overlays, profiles and `.env`
  interpolation beyond `${VAR}` are not resolved. A deployment assembled from overlays is
  only partly described, and the lane reports what it read rather than implying it read
  everything.
- **It does not read Kubernetes manifests.** `privileged: true`, `hostNetwork`, missing
  resource limits and secrets in `env:` are all real and all outside this pack. The
  `container` runtime claims those files; nothing reads them yet, and the inventory says so.
- **It does not read the Dockerfile.** Running as root, `latest` tags and build-time secrets
  are uncovered.
- **`verify_deployment` compares service NAMES to `deployment.published`.** It confirms which
  services are reachable from the host; it does not confirm `network:`, egress, or what a
  firewall in front of the host does.
- **Credential detection is name-based.** A secret in a variable named `CONFIG_BLOB` is
  invisible.
