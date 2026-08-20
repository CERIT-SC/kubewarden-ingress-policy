# CERIT-SC Kubewarden policies

## Installation

### 1. Access to Kubernetes resources

Some of these policies requires access to:
- `networking.k8s.io/v1/Ingress` objects
- `gateway.networking.k8s.io/v1/Gateway` objects
- `gateway.networking.k8s.io/v1/HTTPRoute` objects
- `traefik.io/v1alpha1/IngressRoute` objects

Access to the desired resources could be granted at deployment time of the Kubewarden's `admission-controller` using slightly modified `values.yaml` file.

Here you can find a [sample `values.yaml` file](docs/example-ac-values.yaml) to grant access to the resources.

### 2. Deploy ClusterAdmissionPolicy

```bash
kubectl -n kubewarden apply -f templates/cap-<policy_name>.yaml
```

## Testing in real environment

There is a test script in this repo, that deploys couples of the resources in all combinations to test the policy. The script deploys the resources in two namespaces - `ns-a` and `ns-b`, but its configurable. **Be careful when using this script.**

```bash
cd tests
./test.sh
```

## Building

### Prerequisites

- OPA (Open Policy Agent) CLI for building
- kwctl for annotating and pushing policies
- Credentials for an OCI registry

### Building the Policy

1. Make sure the `opa` and `kwctl` tools are available through the PATH, and that you are logged in to an OCI registry.

2. Build and annotate the policy
```
make annotated-policy.wasm
```

3. Push to registry
```
# For private registries with authentication:
kwctl push --docker-config-json-path ~/.docker/config.json \
  annotated-policy.wasm \
  registry://your-registry.com/namespace/policy-name:tag

# For public registries or already authenticated sessions:
kwctl push annotated-policy.wasm \
  registry://your-registry.com/namespace/policy-name:tag
```
