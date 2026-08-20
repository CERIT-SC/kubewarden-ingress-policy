# cerit-cross-traefik Policy

This policy prevents the creation of Ingress, Gateway, HTTPRoute, and Traefik IngressRoute resources that have host rules conflicting with existing routing resources in **other namespaces**.

**This policy is designed for the Multi-tenancy Kubernetes clusters.**

**Features:**
- Detects exact hostname conflicts across all namespaces
- Supports wildcard hostname matching (e.g., `*.example.com` conflicts with `app.example.com`)
- Path-based conflict detection for Ingress, HTTPRoute, and IngressRoute resources
- Cross-resource type conflict detection (e.g., Ingress vs Gateway, IngressRoute vs HTTPRoute)
- **Allows conflicts within the same namespace** - namespace administrators manage their own resources

> [!WARNING]
> Although asterisk acts as wildcard for **only one level** of a domain name, the policy **detects conflicts even for multi-level** subdomains. E.g.:
>
> `*.example.com` **does** overlap with `app.example.com`, but **doesn't** overlap with `sub.app.example.com`. However this policy detects this case as conflict too.
>
> This is intentional to prevent potential overly complex settings across multiple namespaces.

## Supported Resources

| Kind | API Group | Version |
|------|-----------|---------|
| Ingress | networking.k8s.io | v1 |
| Gateway | gateway.networking.k8s.io | v1 |
| HTTPRoute | gateway.networking.k8s.io | v1 |
| IngressRoute | traefik.io | v1alpha1 |

## Settings

This policy does not take any configuration value.

## Access to Kubernetes resources

Access has to be granted at deployment time by setting the `contextAwareResources`
attribute of the `ClusterAdmissionPolicy`.

Context aware policies cannot be deployed using the `AdmissionPolicy`
custom resource.

Refer to the [context aware documentation](https://docs.kubewarden.io/explanations/context-aware-policies)
for more details.

## Wildcard Hostname Matching

The policy supports wildcard hostnames with the following behavior:

| Incoming Host | Existing Host | Result |
|---------------|---------------|--------|
| `*.example.com` | `*.example.com` | Denied (identical) |
| `*.example.com` | `app.example.com` | Denied (overlap) |
| `*.example.com` | `example.com` | Allowed |
| `*.app.example.com` | `*.other.example.com` | Allowed (different wildcards) |
| `*.example.com` | `app.sub.example.com` | Denied (no overlap, but safer) |

## Path-Based Conflict Detection

For resources that support path matching (Ingress, HTTPRoute, IngressRoute), conflicts only occur when both host AND path match:

| Host 1 | Path 1 | Host 2 | Path 2 | Result |
|--------|--------|--------|--------|--------|
| `app.example.com` | `/`  | `app.example.com` | `/` | Denied (idential) |
| `app.example.com` | `/a` | `app.example.com` | `/b` | Allowed  |
| `app.example.com` | `/`  | `app.example.com` | `/a` | Denied (overlap) |

Gateway resources do not have path matching - any hostname conflict with a Gateway listener is denied.

## Same Namespace Behavior

**Conflicts within the same namespace are allowed.** This policy only detects conflicts across different namespaces. Within a single namespace, it is the responsibility of the namespace administrator to manage resource conflicts.

| Scenario | Namespace | Result |
|----------|-----------|--------|
| `app.example.com` vs `app.example.com` | Different | Denied |
| `app.example.com` vs `app.example.com` | Same | Allowed |
| `*.example.com` vs `app.example.com` | Different | Denied |
| `*.example.com` vs `app.example.com` | Same | Allowed |

## Traefik Match Expression Syntax

Traefik IngressRoute uses match expressions instead of structured fields. Only the `Host`, `Path` and `PathPrefix` are supported.

Examples of the supported patterns:
```
Host(`app.example.com`)                        # Single host, all paths
Host(`app.example.com`) && PathPrefix(`/api`)  # Host with prefix path
Host(`app.example.com`) && Path(`/exact`)      # Host with exact path
Host(`*.example.com`)                          # Wildcard host
Host(`a.com`) || Host(`b.com`)                 # Multiple hosts
```
