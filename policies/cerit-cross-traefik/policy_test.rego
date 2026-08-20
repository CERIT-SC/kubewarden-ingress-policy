package policy

import rego.v1

# =============================================================================
# INVENTORIES
# =============================================================================

inventory_ingress := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-existing": {
	"metadata": {"name": "ing-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

inventory_ingress_wildcard := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-wc": {
	"metadata": {"name": "ing-wc", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

inventory_gateway := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-existing": {
	"metadata": {"name": "gw-existing", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "app.example.com"}]},
}}}}}}

inventory_gateway_wildcard := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-wc": {
	"metadata": {"name": "gw-wc", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "*.example.com"}]},
}}}}}}

inventory_httproute := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-existing": {
	"metadata": {"name": "hr-existing", "namespace": "tenant-a"},
	"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
}}}}}}

inventory_httproute_wildcard := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-wc": {
	"metadata": {"name": "hr-wc", "namespace": "tenant-a"},
	"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
}}}}}}

inventory_traefik := {"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-existing": {
	"metadata": {"name": "ir-existing", "namespace": "tenant-a"},
	"spec": {"routes": [{"match": "Host(`app.example.com`)"}]},
}}}}}}

inventory_traefik_wildcard := {"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-wc": {
	"metadata": {"name": "ir-wc", "namespace": "tenant-a"},
	"spec": {"routes": [{"match": "Host(`*.example.com`)"}]},
}}}}}}

inventory_base := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-base": {
	"metadata": {"name": "ing-base", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

# Multi-level subdomain inputs
review_ingress_multi_sub := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "sub.app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_traefik_multi_sub := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"routes": [{"match": "Host(`sub.app.example.com`)"}]},
	},
}}

# =============================================================================
# INPUTS - Standard kinds (from cerit-cross-kind)
# =============================================================================

review_ingress := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_ingress_wildcard := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_ingress_diff_host := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_gateway := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"listeners": [{"hostname": "app.example.com"}]},
	},
}}

review_gateway_wildcard := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"listeners": [{"hostname": "*.example.com"}]},
	},
}}

review_httproute := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

review_httproute_wildcard := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

review_httproute_diff_path := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
	},
}}

# =============================================================================
# INPUTS - Traefik IngressRoute
# =============================================================================

review_traefik_simple := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"routes": [{"match": "Host(`app.example.com`)"}]},
	},
}}

review_traefik_with_pathprefix := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"routes": [{"match": "Host(`app.example.com`) && PathPrefix(`/api`)"}]},
	},
}}

review_traefik_wildcard := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"routes": [{"match": "Host(`*.example.com`)"}]},
	},
}}

review_traefik_diff_host := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"routes": [{"match": "Host(`other.example.com`)"}]},
	},
}}

# =============================================================================
# TEST CASES - Traefik IngressRoute as input
# =============================================================================

# Traefik vs Ingress
test_traefik_vs_ingress_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_ingress
	count(res) == 1
}

test_traefik_vs_ingress_diff_host_allowed if {
	res := violation with input as review_traefik_diff_host with data.inventory as inventory_ingress
	count(res) == 0
}

# Traefik vs Gateway
test_traefik_vs_gateway_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_gateway
	count(res) == 1
}

test_traefik_vs_gateway_wildcard_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_traefik_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_traefik_simple with data.inventory as diff
	count(res) == 0
}

# Traefik vs HTTPRoute
test_traefik_vs_httproute_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_httproute
	count(res) == 1
}

test_traefik_vs_httproute_wildcard_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

test_traefik_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_traefik_simple with data.inventory as diff
	count(res) == 0
}

# Traefik vs IngressRoute
test_traefik_vs_traefik_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_traefik
	count(res) == 1
}

test_traefik_vs_traefik_wildcard_rejected if {
	res := violation with input as review_traefik_simple with data.inventory as inventory_traefik_wildcard
	count(res) == 1
}

test_traefik_wildcard_vs_traefick_rejected if {
	res := violation with input as review_traefik_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

test_traefik_vs_traefik_diff_path_allowed if {
	diff := {"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-dpath": {
		"metadata": {"name": "ir-dpath", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`app.example.com`) && PathPrefix(`/web`)"}]},
	}}}}}}
	res := violation with input as review_traefik_with_pathprefix with data.inventory as diff
	count(res) == 0
}

# Multi-level subdomain tests
test_traefik_multi_sub_vs_wildcard_rejected if {
	res := violation with input as review_traefik_multi_sub with data.inventory as inventory_traefik_wildcard
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

# =============================================================================
# TEST CASES - Other kinds vs Traefik (reverse direction)
# =============================================================================

# Ingress vs Traefik
test_ingress_vs_traefik_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_traefik
	count(res) == 1
}

test_ingress_vs_traefik_wildcard_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

test_ingress_vs_traefik_diff_host_allowed if {
	res := violation with input as review_ingress_diff_host with data.inventory as inventory_traefik
	count(res) == 0
}

# Gateway vs Traefik
test_gateway_vs_traefik_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_traefik
	count(res) == 1
}

test_gateway_vs_traefik_wildcard_rejected if {
	res := violation with input as review_gateway_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

test_gateway_vs_traefik_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-other": {
		"metadata": {"name": "ir-other", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`other.example.com`)"}]},
	}}}}}}
	res := violation with input as review_gateway with data.inventory as diff
	count(res) == 0
}

# HTTPRoute vs Traefik
test_httproute_vs_traefik_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_traefik
	count(res) == 1
}

test_httproute_vs_traefik_wildcard_rejected if {
	res := violation with input as review_httproute_wildcard with data.inventory as inventory_traefik
	count(res) == 1
}

test_httproute_vs_traefik_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-other": {
		"metadata": {"name": "ir-other", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`other.example.com`)"}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff
	count(res) == 0
}

test_httproute_vs_traefik_diff_path_allowed if {
	diff := {"namespace": {"tenant-a": {"traefik.io/v1alpha1": {"IngressRoute": {"ir-dpath": {
		"metadata": {"name": "ir-dpath", "namespace": "tenant-a"},
		"spec": {"routes": [{"match": "Host(`app.example.com`) && PathPrefix(`/web`)"}]},
	}}}}}}
	res := violation with input as review_httproute_diff_path with data.inventory as diff
	count(res) == 0
}

# =============================================================================
# SAME-NAMESPACE TEST CASES - Conflicts within same namespace are ALLOWED
# =============================================================================

# Same namespace inputs (all use tenant-a namespace)
review_ingress_same_ns := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_ingress_wildcard_same_ns := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_gateway_same_ns := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"listeners": [{"hostname": "app.example.com"}]},
	},
}}

review_gateway_wildcard_same_ns := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"listeners": [{"hostname": "*.example.com"}]},
	},
}}

review_httproute_same_ns := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

review_httproute_wildcard_same_ns := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

review_traefik_simple_same_ns := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"routes": [{"match": "Host(`app.example.com`)"}]},
	},
}}

review_traefik_wildcard_same_ns := {"review": {
	"kind": {"group": "traefik.io", "version": "v1alpha1", "kind": "IngressRoute"},
	"object": {
		"metadata": {"namespace": "tenant-a", "name": "test-new"},
		"spec": {"routes": [{"match": "Host(`*.example.com`)"}]},
	},
}}

# Same namespace: Ingress vs Ingress (should be ALLOWED)
test_ingress_same_ns_allowed if {
	res := violation with input as review_ingress_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

# Same namespace: Ingress wildcard vs Ingress (should be ALLOWED)
test_ingress_wildcard_same_ns_allowed if {
	res := violation with input as review_ingress_wildcard_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

# Same namespace: Gateway vs Ingress (should be ALLOWED)
test_gateway_same_ns_vs_ingress_allowed if {
	res := violation with input as review_gateway_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

# Same namespace: Gateway vs Gateway (should be ALLOWED)
test_gateway_same_ns_allowed if {
	res := violation with input as review_gateway_same_ns with data.inventory as inventory_gateway
	count(res) == 0
}

# Same namespace: HTTPRoute vs Ingress (should be ALLOWED)
test_httproute_same_ns_vs_ingress_allowed if {
	res := violation with input as review_httproute_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

# Same namespace: HTTPRoute vs Gateway (should be ALLOWED)
test_httproute_same_ns_allowed if {
	res := violation with input as review_httproute_same_ns with data.inventory as inventory_gateway
	count(res) == 0
}

# Same namespace: IngressRoute vs Ingress (should be ALLOWED)
test_traefik_same_ns_vs_ingress_allowed if {
	res := violation with input as review_traefik_simple_same_ns with data.inventory as inventory_ingress
	count(res) == 0
}

# Same namespace: IngressRoute vs Gateway (should be ALLOWED)
test_traefik_same_ns_vs_gateway_allowed if {
	res := violation with input as review_traefik_simple_same_ns with data.inventory as inventory_gateway
	count(res) == 0
}

# Same namespace: IngressRoute vs HTTPRoute (should be ALLOWED)
test_traefik_same_ns_vs_httproute_allowed if {
	res := violation with input as review_traefik_simple_same_ns with data.inventory as inventory_httproute
	count(res) == 0
}

# Same namespace: IngressRoute vs IngressRoute (should be ALLOWED)
test_traefik_same_ns_allowed if {
	res := violation with input as review_traefik_simple_same_ns with data.inventory as inventory_traefik
	count(res) == 0
}

# Same namespace: Ingress vs IngressRoute (should be ALLOWED)
test_ingress_same_ns_vs_traefik_allowed if {
	res := violation with input as review_ingress_same_ns with data.inventory as inventory_traefik
	count(res) == 0
}

# Same namespace: Gateway vs IngressRoute (should be ALLOWED)
test_gateway_same_ns_vs_traefik_allowed if {
	res := violation with input as review_gateway_same_ns with data.inventory as inventory_traefik
	count(res) == 0
}

# Same namespace: HTTPRoute vs IngressRoute (should be ALLOWED)
test_httproute_same_ns_vs_traefik_allowed if {
	res := violation with input as review_httproute_same_ns with data.inventory as inventory_traefik
	count(res) == 0
}

# Same namespace: Wildcard conflicts allowed too
test_ingress_wildcard_same_ns_vs_wildcard_allowed if {
	res := violation with input as review_ingress_wildcard_same_ns with data.inventory as inventory_ingress_wildcard
	count(res) == 0
}

test_gateway_wildcard_same_ns_allowed if {
	res := violation with input as review_gateway_wildcard_same_ns with data.inventory as inventory_gateway_wildcard
	count(res) == 0
}

test_httproute_wildcard_same_ns_allowed if {
	res := violation with input as review_httproute_wildcard_same_ns with data.inventory as inventory_httproute_wildcard
	count(res) == 0
}

test_traefik_wildcard_same_ns_allowed if {
	res := violation with input as review_traefik_wildcard_same_ns with data.inventory as inventory_traefik_wildcard
	count(res) == 0
}
