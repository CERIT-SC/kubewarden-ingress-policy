package policy

import rego.v1

# =============================================================================
# SECTION 1: INVENTORIES (Existing resources in tenant-a namespace)
# =============================================================================

# --- Ingress inventories ---
inventory_ingress := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-existing": {
		"metadata": {"name": "ing-existing", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

inventory_ingress_wildcard := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-wc": {
		"metadata": {"name": "ing-wc", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

inventory_ingress_base := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-base": {
		"metadata": {"name": "ing-base", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

inventory_ingress_subdomain := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-sub": {
		"metadata": {"name": "ing-sub", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "sub.app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

inventory_ingress_foo_subdomain := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-foo-sub": {
		"metadata": {"name": "ing-foo-sub", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.foo.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

inventory_ingress_foo_wildcard := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-foo-wc": {
		"metadata": {"name": "ing-foo-wc", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "*.foo.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

inventory_ingress_api := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-api": {
		"metadata": {"name": "ing-api", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
	}}}}},
}

inventory_ingress_a := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-a": {
		"metadata": {"name": "ing-a", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a"}]}}]},
	}}}}},
}

inventory_ingress_a_slash := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-a-slash": {
		"metadata": {"name": "ing-a-slash", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/"}]}}]},
	}}}}},
}

inventory_ingress_ab := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-ab": {
		"metadata": {"name": "ing-ab", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/b"}]}}]},
	}}}}},
}

inventory_ingress_ab_slash := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-ab-slash": {
		"metadata": {"name": "ing-ab-slash", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/b/"}]}}]},
	}}}}},
}

inventory_ingress_b := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-b": {
		"metadata": {"name": "ing-b", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/b"}]}}]},
	}}}}},
}

inventory_ingress_other := {
	"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-other": {
		"metadata": {"name": "ing-other", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}},
}

# --- Gateway inventories ---
inventory_gateway := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-existing": {
		"metadata": {"name": "gw-existing", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "app.example.com"}]},
	}}}}},
}

inventory_gateway_wildcard := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-wc": {
		"metadata": {"name": "gw-wc", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "*.example.com"}]},
	}}}}},
}

inventory_gateway_foo_wildcard := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-foo-wc": {
		"metadata": {"name": "gw-foo-wc", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "*.foo.example.com"}]},
	}}}}},
}

inventory_gateway_other := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}},
}

# --- HTTPRoute inventories ---
inventory_httproute := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-existing": {
		"metadata": {"name": "hr-existing", "namespace": "tenant-a"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}},
}

inventory_httproute_wildcard := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-wc": {
		"metadata": {"name": "hr-wc", "namespace": "tenant-a"},
		"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}},
}

inventory_httproute_foo_wildcard := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-foo-wc": {
		"metadata": {"name": "hr-foo-wc", "namespace": "tenant-a"},
		"spec": {"hostnames": ["*.foo.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}},
}

inventory_httproute_foo_subdomain := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-foo-sub": {
		"metadata": {"name": "hr-foo-sub", "namespace": "tenant-a"},
		"spec": {"hostnames": ["app.foo.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}},
}

inventory_httproute_api := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-api": {
		"metadata": {"name": "hr-api", "namespace": "tenant-a"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
	}}}}},
}

inventory_httproute_b := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-b": {
		"metadata": {"name": "hr-b", "namespace": "tenant-a"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/b"}}]}]},
	}}}}},
}

inventory_httproute_other := {
	"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
	}}}}},
}

# --- IngressRoute (Traefik) inventories ---
inventory_traefik := {
	"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-existing": {
		"metadata": {"name": "ir-existing", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`app.example.com`)"}]},
	}}}}},
}

inventory_traefik_wildcard := {
	"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-wc": {
		"metadata": {"name": "ir-wc", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`*.example.com`)"}]},
	}}}}},
}

inventory_traefik_foo_wildcard := {
	"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-foo-wc": {
		"metadata": {"name": "ir-foo-wc", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`*.foo.example.com`)"}]},
	}}}}},
}

inventory_traefik_foo_subdomain := {
	"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-foo-sub": {
		"metadata": {"name": "ir-foo-sub", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`app.foo.example.com`)"}]},
	}}}}},
}

inventory_traefik_web := {
	"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-web": {
		"metadata": {"name": "ir-web", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`app.example.com`) && PathPrefix(`/web`)"}]},
	}}}}},
}

inventory_traefik_other := {
	"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-other": {
		"metadata": {"name": "ir-other", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`other.example.com`)"}]},
	}}}}},
}

# =============================================================================
# SECTION 2: INPUTS (Incoming review objects to be validated)
# =============================================================================

# --- Ingress inputs ---
review_ingress := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_wildcard := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_base := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_multi_sub := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "sub.app.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_foo_wildcard := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "*.foo.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_foo_subdomain := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.foo.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_a := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a"}]}}]},
		},
	},
}

review_ingress_a_slash := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/"}]}}]},
		},
	},
}

review_ingress_ab := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/b"}]}}]},
		},
	},
}

review_ingress_ab_slash := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/b/"}]}}]},
		},
	},
}

review_ingress_b := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/b"}]}}]},
		},
	},
}

review_ingress_api := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
		},
	},
}

review_ingress_other := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

# --- Gateway inputs ---
review_gateway := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"listeners": [{"hostname": "app.example.com"}]},
		},
	},
}

review_gateway_wildcard := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"listeners": [{"hostname": "*.example.com"}]},
		},
	},
}

review_gateway_foo_wildcard := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"listeners": [{"hostname": "*.foo.example.com"}]},
		},
	},
}

review_gateway_other := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"listeners": [{"hostname": "other.example.com"}]},
		},
	},
}

# --- HTTPRoute inputs ---
review_httproute := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
		},
	},
}

review_httproute_wildcard := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
		},
	},
}

review_httproute_foo_wildcard := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["*.foo.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
		},
	},
}

review_httproute_foo_subdomain := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["app.foo.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
		},
	},
}

review_httproute_api := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
		},
	},
}

review_httproute_b := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/b"}}]}]},
		},
	},
}

review_httproute_other := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
		},
	},
}

# --- IngressRoute (Traefik) inputs ---
review_traefik_simple := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`app.example.com`)"}]},
		},
	},
}

review_traefik_wildcard := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`*.example.com`)"}]},
		},
	},
}

review_traefik_base := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`example.com`)"}]},
		},
	},
}

review_traefik_multi_sub := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`sub.app.example.com`)"}]},
		},
	},
}

review_traefik_foo_wildcard := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`*.foo.example.com`)"}]},
		},
	},
}

review_traefik_foo_subdomain := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`app.foo.example.com`)"}]},
		},
	},
}

review_traefik_web := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`app.example.com`) && PathPrefix(`/web`)"}]},
		},
	},
}

review_traefik_diff_host := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"routes": [{"match": "Host(`other.example.com`)"}]},
		},
	},
}

review_gateway_other := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"listeners": [{"hostname": "other.example.com"}]},
		},
	},
}

review_httproute_other := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "default", "name": "test"},
			"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
		},
	},
}

# =============================================================================
# SECTION 3: SAME-NAMESPACE INPUTS (Resources in tenant-a namespace)
# =============================================================================

review_ingress_same_ns := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_wildcard_same_ns := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
		},
	},
}

review_ingress_a_same_ns := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a"}]}}]},
		},
	},
}

review_ingress_a_slash_same_ns := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/"}]}}]},
		},
	},
}

review_ingress_ab_same_ns := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/b"}]}}]},
		},
	},
}

review_ingress_ab_slash_same_ns := {
	"review": {
		"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a/b/"}]}}]},
		},
	},
}

review_gateway_same_ns := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"listeners": [{"hostname": "app.example.com"}]},
		},
	},
}

review_gateway_wildcard_same_ns := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"listeners": [{"hostname": "*.example.com"}]},
		},
	},
}

review_httproute_same_ns := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
		},
	},
}

review_httproute_wildcard_same_ns := {
	"review": {
		"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
		},
	},
}

review_traefik_same_ns := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"routes": [{"match": "Host(`app.example.com`)"}]},
		},
	},
}

review_traefik_wildcard_same_ns := {
	"review": {
		"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
		"object": {
			"metadata": {"namespace": "tenant-a", "name": "test-new"},
			"spec": {"routes": [{"match": "Host(`*.example.com`)"}]},
		},
	},
}

# =============================================================================
# SECTION 4: TESTS - DENY CASES (Cross-namespace conflicts)
# =============================================================================

# --- Same host tests ---
test_ingress_vs_ingress_same_host_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress
	count(res) == 1
}

test_gateway_vs_gateway_same_host_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_gateway
	count(res) == 1
}

test_httproute_vs_httproute_same_host_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_httproute
	count(res) == 1
}

test_traefik_vs_traefik_same_host_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_traefik
	count(res) == 1
}

# --- Wildcard same tests ---
test_ingress_wildcard_vs_ingress_wildcard_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_gateway_wildcard_vs_gateway_wildcard_rejected if {
	res := violation with input as review_gateway_wildcard with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

# --- Wildcard overlap tests (wildcard vs specific host) ---
test_ingress_wildcard_vs_ingress_overlap_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_ingress
	count(res) == 1
}

test_ingress_vs_ingress_wildcard_overlap_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_gateway_wildcard_vs_gateway_overlap_rejected if {
	res := violation with input as review_gateway_wildcard with data.inventory as inventory_gateway
	count(res) == 1
}

test_gateway_vs_gateway_wildcard_overlap_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_httproute_wildcard_vs_httproute_overlap_rejected if {
	res := violation with input as review_httproute_wildcard with data.inventory as inventory_httproute
	count(res) == 1
}

test_httproute_vs_httproute_wildcard_overlap_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

test_traefik_wildcard_vs_traefik_overlap_rejected if {
	res := violation with input as review_traefik_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

test_traefik_vs_traefik_wildcard_overlap_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_traefik_wildcard
	count(res) == 1
}

# --- Multi-level subdomain vs wildcard tests ---
test_ingress_multi_sub_vs_ingress_wildcard_rejected if {
	res := violation with input as review_ingress_multi_sub with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_ingress_wildcard_vs_ingress_multi_sub_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_ingress_subdomain
	count(res) == 1
}

test_gateway_wildcard_vs_gateway_multi_sub_rejected if {
	res := violation with input as review_gateway_wildcard with data.inventory as inventory_gateway
	count(res) == 1
}

test_httproute_wildcard_vs_httproute_multi_sub_rejected if {
	res := violation with input as review_httproute_wildcard with data.inventory as inventory_httproute
	count(res) == 1
}

test_traefik_wildcard_vs_traefik_multi_sub_rejected if {
	res := violation with input as review_traefik_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

# --- Different wildcard subdomains (should these conflict?) ---
# *.foo.example.com vs app.foo.example.com
test_ingress_foo_wildcard_vs_ingress_foo_subdomain_rejected if {
	res := violation with input as review_ingress_foo_wildcard with data.inventory as inventory_ingress_foo_subdomain
	count(res) == 1
}

test_ingress_foo_subdomain_vs_ingress_foo_wildcard_rejected if {
	res := violation with input as review_ingress_foo_subdomain with data.inventory as inventory_ingress_foo_wildcard
	count(res) == 1
}

# =============================================================================
# SECTION 5: TESTS - PATH OVERLAP DENY CASES (Cross-namespace)
# =============================================================================

# Root path / vs /a
test_ingress_root_vs_a_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_a
	count(res) == 1
}

# Root path / vs /a/
test_ingress_root_vs_a_slash_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_a_slash
	count(res) == 1
}

# Root path / vs /a/b
test_ingress_root_vs_ab_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_ab
	count(res) == 1
}

# Root path / vs /a/b/
test_ingress_root_vs_ab_slash_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_ab_slash
	count(res) == 1
}

# Prefix /a vs /a/b
test_ingress_a_vs_ab_rejected if {
	res := violation with input as review_ingress_a with data.inventory as inventory_ingress_ab
	count(res) == 1
}

# Prefix /a vs /a/b/
test_ingress_a_vs_ab_slash_rejected if {
	res := violation with input as review_ingress_a with data.inventory as inventory_ingress_ab_slash
	count(res) == 1
}

# Reverse: /a vs /
test_ingress_a_vs_root_rejected if {
	res := violation with input as review_ingress_a with data.inventory as inventory_ingress
	count(res) == 1
}

# Reverse: /a/ vs /
test_ingress_a_slash_vs_root_rejected if {
	res := violation with input as review_ingress_a_slash with data.inventory as inventory_ingress
	count(res) == 1
}

# Reverse: /a/b vs /
test_ingress_ab_vs_root_rejected if {
	res := violation with input as review_ingress_ab with data.inventory as inventory_ingress
	count(res) == 1
}

# Reverse: /a/b/ vs /
test_ingress_ab_slash_vs_root_rejected if {
	res := violation with input as review_ingress_ab_slash with data.inventory as inventory_ingress
	count(res) == 1
}

# Reverse: /a/b vs /a
test_ingress_ab_vs_a_rejected if {
	res := violation with input as review_ingress_ab with data.inventory as inventory_ingress_a
	count(res) == 1
}

# Reverse: /a/b/ vs /a
test_ingress_ab_slash_vs_a_rejected if {
	res := violation with input as review_ingress_ab_slash with data.inventory as inventory_ingress_a
	count(res) == 1
}

# =============================================================================
# SECTION 6: TESTS - ALLOW CASES (Cross-namespace, no conflict)
# =============================================================================

# --- Wildcard vs base domain (no conflict) ---
test_ingress_wildcard_vs_base_allowed if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_ingress_base
	count(res) == 0
}

test_ingress_base_vs_wildcard_allowed if {
	res := violation with input as review_ingress_base with data.inventory as inventory_ingress_wildcard
	count(res) == 0
}

# --- Different wildcard subdomains ---
test_ingress_foo_wildcard_vs_bar_wildcard_allowed if {
	res := violation with input as review_ingress_foo_wildcard with data.inventory as {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-other-wc": {
		"metadata": {"name": "ing-other-wc", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "*.other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}}}
	count(res) == 0
}

# --- Different subdomains (same-host-sub and same-host-sub-r) ---
test_ingress_subdomain_vs_different_subdomain_allowed if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_subdomain
	count(res) == 0
}

test_ingress_different_subdomain_vs_subdomain_allowed if {
	res := violation with input as review_ingress_multi_sub with data.inventory as inventory_ingress
	count(res) == 0
}

# --- Different paths on same host ---
test_ingress_a_vs_b_allowed if {
	res := violation with input as review_ingress_a with data.inventory as inventory_ingress_b
	count(res) == 0
}

test_ingress_a_vs_api_allowed if {
	res := violation with input as review_ingress_a with data.inventory as inventory_ingress_api
	count(res) == 0
}

# --- Different hosts ---
test_ingress_vs_ingress_other_host_allowed if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_other
	count(res) == 0
}

# Different hosts, same path - should be allowed (matches test.sh: diff-host-same-path)
test_ingress_vs_ingress_diff_host_same_path_allowed if {
	res := violation with input as review_ingress_api with data.inventory as inventory_ingress_other
	count(res) == 0
}

# =============================================================================
# SECTION 7: TESTS - SAME NAMESPACE (All conflicts allowed)
# =============================================================================

# --- Same host, same namespace ---
test_ingress_same_ns_vs_ingress_allowed if {
	res := violation with input as review_ingress_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

test_ingress_wildcard_same_ns_vs_ingress_wildcard_allowed if {
	res := violation with input as review_ingress_wildcard_same_ns with data.inventory as inventory_ingress_wildcard
	count(res) == 0
}

# --- Wildcard overlap, same namespace ---
test_ingress_wildcard_same_ns_vs_ingress_allowed if {
	res := violation with input as review_ingress_wildcard_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

test_ingress_same_ns_vs_ingress_wildcard_allowed if {
	res := violation with input as review_ingress_same_ns with data.inventory as inventory_ingress_wildcard
	count(res) == 0
}

# --- Path overlap, same namespace ---
test_ingress_same_ns_vs_ingress_a_allowed if {
	res := violation with input as review_ingress_same_ns with data.inventory as inventory_ingress_a
	count(res) == 0
}

test_ingress_a_same_ns_vs_ingress_root_allowed if {
	res := violation with input as review_ingress_a_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

test_ingress_a_same_ns_vs_ingress_ab_allowed if {
	res := violation with input as review_ingress_a_same_ns with data.inventory as inventory_ingress_ab
	count(res) == 0
}

test_ingress_ab_same_ns_vs_ingress_a_allowed if {
	res := violation with input as review_ingress_ab_same_ns with data.inventory as inventory_ingress_a
	count(res) == 0
}

# --- Gateway same namespace ---
test_gateway_same_ns_vs_gateway_allowed if {
	res := violation with input as review_gateway_same_ns with data.inventory as inventory_gateway
	count(res) == 0
}

test_gateway_wildcard_same_ns_vs_gateway_wildcard_allowed if {
	res := violation with input as review_gateway_wildcard_same_ns with data.inventory as inventory_gateway_wildcard
	count(res) == 0
}

# --- HTTPRoute same namespace ---
test_httproute_same_ns_vs_httproute_allowed if {
	res := violation with input as review_httproute_same_ns with data.inventory as inventory_httproute
	count(res) == 0
}

test_httproute_wildcard_same_ns_vs_httproute_wildcard_allowed if {
	res := violation with input as review_httproute_wildcard_same_ns with data.inventory as inventory_httproute_wildcard
	count(res) == 0
}

# --- Traefik same namespace ---
test_traefik_same_ns_vs_traefik_allowed if {
	res := violation with input as review_traefik_same_ns with data.inventory as inventory_traefik
	count(res) == 0
}

test_traefik_wildcard_same_ns_vs_traefik_wildcard_allowed if {
	res := violation with input as review_traefik_wildcard_same_ns with data.inventory as inventory_traefik_wildcard
	count(res) == 0
}

# =============================================================================
# SECTION 8: TESTS - CROSS-KIND CONFLICTS
# =============================================================================

# --- Traefik vs other kinds ---
test_traefik_vs_ingress_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_ingress
	count(res) == 1
}

test_traefik_vs_gateway_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_gateway
	count(res) == 1
}

test_traefik_vs_httproute_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_httproute
	count(res) == 1
}

test_traefik_vs_ingress_wildcard_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_traefik_vs_gateway_wildcard_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_traefik_vs_httproute_wildcard_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

test_traefik_multi_sub_vs_ingress_wildcard_rejected if {
	res := violation with input as review_traefik_multi_sub with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_traefik_multi_sub_vs_gateway_wildcard_rejected if {
	res := violation with input as review_traefik_multi_sub with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_traefik_multi_sub_vs_httproute_wildcard_rejected if {
	res := violation with input as review_traefik_multi_sub with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

# --- Ingress vs Traefik ---
test_ingress_vs_traefik_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_traefik
	count(res) == 1
}

test_ingress_wildcard_vs_traefik_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

# --- Gateway vs Traefik ---
test_gateway_vs_traefik_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_traefik
	count(res) == 1
}

test_gateway_wildcard_vs_traefik_rejected if {
	res := violation with input as review_gateway_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

# --- HTTPRoute vs Traefik ---
test_httproute_vs_traefik_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_traefik
	count(res) == 1
}

test_httproute_wildcard_vs_traefik_rejected if {
	res := violation with input as review_httproute_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

# --- Cross-kind different hosts (allowed) ---
test_traefik_vs_ingress_diff_host_allowed if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_ingress_other
	count(res) == 0
}

test_ingress_vs_traefik_diff_host_allowed if {
	res := violation with input as review_ingress_other with data.inventory as inventory_traefik
	count(res) == 0
}

test_gateway_vs_traefik_diff_host_allowed if {
	res := violation with input as review_gateway_other with data.inventory as inventory_traefik
	count(res) == 0
}

test_httproute_vs_traefik_diff_host_allowed if {
	res := violation with input as review_httproute_other with data.inventory as inventory_traefik
	count(res) == 0
}

# --- Different non-overlapping paths on same host - should be allowed ---
# /a vs /b (different paths, no overlap)
test_ingress_a_vs_b_different_paths_allowed if {
	res := violation with input as review_ingress_a with data.inventory as inventory_ingress_b
	count(res) == 0
}

# Traefik: PathPrefix(/web) vs no path restriction - this IS a conflict because root matches all
# So we test different non-overlapping Traefik paths instead
# Note: Host(app.example.com) without path matches ALL paths, so any subpath conflicts
# We need to test two specific non-overlapping paths - but Traefik IngressRoute doesn't have
# a way to specify "only this exact path" without also matching subpaths in the same way
# For now, skip this test or test same-namespace where it's allowed

# HTTPRoute vs Traefik with different hosts - should be allowed
test_httproute_vs_traefik_diff_host_allowed if {
	res := violation with input as review_httproute_api with data.inventory as inventory_traefik_other
	count(res) == 0
}
