# Deployment Guide

## Prerequisites

- OPA (Open Policy Agent) CLI for building
- kwctl for annotating and pushing policies
- Docker credentials for your registry

## Building the Policy

1. Make sure the `opa` and `kwctl` tools are available through the PATH

0. Build and annotate the policy
```
make annotated-policy.wasm
```

0. Push to registry
```
# For private registries with authentication:
kwctl push --docker-config-json-path ~/.docker/config.json \
  annotated-policy.wasm \
  registry://your-registry.com/namespace/policy-name:tag

# For public registries or already authenticated sessions:
kwctl push annotated-policy.wasm \
  registry://your-registry.com/namespace/policy-name:tag
```
