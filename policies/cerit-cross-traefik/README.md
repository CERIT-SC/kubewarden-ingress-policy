# cerit-cross-traefik Policy

## Overview

The `cerit-cross-traefik` policy extends hostname conflict detection to include **Traefik IngressRoute** resources alongside the standard Kubernetes networking kinds (Ingress, Gateway, HTTPRoute).

This policy ensures that no two routing resources conflict on the same hostname and path combination within a namespace.

## Supported Resources

| Kind | API Group | Version |
|------|-----------|---------|
| Ingress | networking.k8s.io | v1 |
| Gateway | gateway.networking.k8s.io | v1 |
| HTTPRoute | gateway.networking.k8s.io | v1 |
| IngressRoute | traefik.io | v1alpha1 |

## Conflict Detection

### Hostname Conflicts

The policy detects conflicts for:
- **Exact host match**: `app.example.com` vs `app.example.com`
- **Wildcard overlap**: `*.example.com` vs `app.example.com`
- **Multi-level subdomain**: `sub.app.example.com` vs `*.example.com`

### Path Conflicts

For resources that support paths:
- **Exact path match**: `/api` vs `/api`
- **Empty path**: Empty path (all paths) conflicts with any specific path

### Cross-Kind Conflicts

All combinations are checked:
- IngressRoute vs Ingress, Gateway, HTTPRoute, IngressRoute
- Ingress vs IngressRoute
- Gateway vs IngressRoute
- HTTPRoute vs IngressRoute

## Traefik Match Expression Syntax

Traefik IngressRoute uses match expressions instead of structured fields:

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: example
  namespace: default
spec:
  routes:
    - match: Host(`app.example.com`) && PathPrefix(`/api`)
      kind: Rule
      services:
        - name: my-service
          port: 80
```

### Supported Match Patterns

| Expression | Meaning |
|------------|---------|
| `Host(`app.example.com`)` | Single host, all paths |
| `Host(`app.example.com`) && PathPrefix(`/api`)` | Host with prefix path |
| `Host(`app.example.com`) && Path(`/exact`)` | Host with exact path |
| `Host(`*.example.com`)` | Wildcard host |
| `Host(`a.com`) || Host(`b.com`)` | Multiple hosts |

## Examples

### Denied: Duplicate Host

```yaml
# Existing IngressRoute
spec:
  routes:
    - match: Host(`app.example.com`)

# New IngressRoute - DENIED
spec:
  routes:
    - match: Host(`app.example.com`)
```

### Denied: Wildcard Overlap

```yaml
# Existing IngressRoute with wildcard
spec:
  routes:
    - match: Host(`*.example.com`)

# New IngressRoute - DENIED (matches wildcard)
spec:
  routes:
    - match: Host(`app.example.com`)
```

### Allowed: Different Host

```yaml
# Existing IngressRoute
spec:
  routes:
    - match: Host(`app.example.com`)

# New IngressRoute - ALLOWED
spec:
  routes:
    - match: Host(`other.example.com`)
```

### Allowed: Different Path

```yaml
# Existing IngressRoute
spec:
  routes:
    - match: Host(`app.example.com`) && PathPrefix(`/api`)

# New IngressRoute - ALLOWED (different path)
spec:
  routes:
    - match: Host(`app.example.com`) && PathPrefix(`/web`)
```

## Building

```bash
make OPA_V0_COMPATIBLE=false
```

## Testing

```bash
opa test -v policy.rego policy_test.rego
```

## See Also

- [cerit-cross-kind](../cerit-cross-kind/README.md) - Standard cross-kind policy without Traefik
- [cerit-unique-ingress](../cerit-unique-ingress/README.md) - Ingress-only policy
