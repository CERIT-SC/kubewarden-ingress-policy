# Multi-Gateway Host Policy

This policy prevents the creation of Ingress, Gateway, and HTTPRoute resources that have host rules conflicting with existing routing resources in the cluster.

**Features:**
- Detects exact hostname conflicts across all namespaces
- Supports wildcard hostname matching (e.g., `*.example.com` conflicts with `app.example.com`)
- Path-based conflict detection for Ingress and HTTPRoute resources
- Cross-resource type conflict detection (e.g., Ingress vs Gateway, HTTPRoute vs Ingress)

**Note:** This policy does not handle hostname wildcards for multi-level subdomains beyond one label. For example, `*.example.com` matches `app.example.com` but NOT `app.sub.example.com`.

## Access to Kubernetes resources

This policy requires access to:
- `networking.k8s.io/v1/Ingress` objects
- `gateway.networking.k8s.io/v1/Gateway` objects
- `gateway.networking.k8s.io/v1/HTTPRoute` objects

Access has to be granted at deployment time by setting the `contextAwareResources`
attribute of the `ClusterAdmissionPolicy`.

Note: context aware policies cannot be deployed using the `AdmissionPolicy`
custom resource.

Refer to the [context aware documentation](https://docs.kubewarden.io/explanations/context-aware-policies)
for more details.

## Settings

This policy does not take any configuration value.

## Wildcard Hostname Matching

The policy supports wildcard hostnames with the following behavior:

| Incoming Host | Existing Host | Result |
|---------------|---------------|--------|
| `*.example.com` | `*.example.com` | Denied (identical) |
| `*.example.com` | `app.example.com` | Denied (overlap) |
| `app.example.com` | `*.example.com` | Denied (overlap) |
| `*.example.com` | `example.com` | Allowed |
| `*.app.example.com` | `*.other.example.com` | Allowed (different wildcards) |
| `*.example.com` | `app.sub.example.com` | Allowed (multi-level subdomain) |

## Path-Based Conflict Detection

For resources that support path matching (Ingress, HTTPRoute), conflicts only occur when both host AND path match:

| Resource 1 | Host 1 | Path 1 | Resource 2 | Host 2 | Path 2 | Result |
|------------|--------|--------|------------|--------|--------|--------|
| Ingress | `app.example.com` | `/` | Ingress | `app.example.com` | `/` | Denied |
| Ingress | `app.example.com` | `/a` | Ingress | `app.example.com` | `/b` | Allowed |
| HTTPRoute | `app.example.com` | `/api` | HTTPRoute | `app.example.com` | `/api` | Denied |
| Ingress | `app.example.com` | `/` | HTTPRoute | `app.example.com` | `/` | Denied |

Gateway resources do not have path matching - any hostname conflict with a Gateway listener is denied.

## Implementation details

This policy extends the [unique-ingress-host policy](../cerit-unique-ingress/README.md) to also check:
- Gateway (gateway.networking.k8s.io/v1) resources - listener.hostname field
- HTTPRoute (gateway.networking.k8s.io/v1) resources - spec.hostnames and spec.rules[].matches[].path
