# Cerit Ingress Policy

This policy prevents the creation of Ingress resources that have host rules conflicting with the Ingress objects already defined inside of the cluster.

**Features:**
- Detects exact hostname conflicts across all namespaces
- Supports wildcard hostname matching (e.g., `*.example.com` conflicts with `app.example.com`)
- Path-based conflict detection: same host with different paths is allowed

**Note:** This policy does not handle hostname wildcards for multi-level subdomains beyond one label. For example, `*.example.com` matches `app.example.com` but NOT `app.sub.example.com`.

## Access to Kubernetes resources

This policy requires access to `networking.k8s.io/Ingress` objects.
Access has to be granted at deployment time by setting the `contextAwareResources`
attribute of the `ClusterAdmissionPolicy`.

Note: context aware policies cannot be deployed using the `AdmissionPolicy`
custom resource.

Refer to the [context aware documentation](https://docs.kubewarden.io/explanations/context-aware-policies)
for more details.

## Settings

This policy does not take any configuration value.

This is a Gatekeeper policy that prevents the creation of Ingress resources
with duplicated hosts, extended with wildcard and path support.

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

The policy checks both hostname AND path. Conflicts only occur when both match:

| Incoming Host | Incoming Path | Existing Host | Existing Path | Result |
|---------------|---------------|---------------|---------------|--------|
| `app.example.com` | `/` | `app.example.com` | `/` | Denied |
| `app.example.com` | `/a` | `app.example.com` | `/b` | Allowed |
| `app.example.com` | `/api` | `other.example.com` | `/api` | Allowed |
| `app.example.com` | `/` | `sub.app.example.com` | `/` | Allowed |


## Implementation details

The policy is based on the [Gatekeeper unique ingress host policy](https://open-policy-agent.github.io/gatekeeper-library/website/validation/uniqueingresshost/),
extended with:
- Wildcard hostname matching support
- Path-based conflict detection
