package policy

import rego.v1

# =============================================================================
# TEST INVENTORY - Single Ingress
# =============================================================================

inventory_ingress := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-existing": {
	"metadata": {"name": "ing-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

# =============================================================================
# TEST INPUTS
# =============================================================================

review_ingress_same := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_ingress_diff_host := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_ingress_diff_path := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
	},
}}

# Wildcard inventory
inventory_wildcard := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-wc": {
	"metadata": {"name": "ing-wc", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

# Wildcard input
review_ingress_wildcard := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

# Subdomain input
review_ingress_subdomain := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

# =============================================================================
# TEST CASES - Ingress vs Ingress ONLY
# =============================================================================

# REJECT: exact host and path match
test_ingress_vs_ingress_rejected if {
	res := violation with input as review_ingress_same with data.inventory as inventory_ingress
	count(res) == 1
}

# ALLOW: different host
test_ingress_different_host_allowed if {
	res := violation with input as review_ingress_diff_host with data.inventory as inventory_ingress
	count(res) == 0
}

# ALLOW: same host, different path
test_ingress_same_host_diff_path_allowed if {
	res := violation with input as review_ingress_diff_path with data.inventory as inventory_ingress
	count(res) == 0
}

# REJECT: wildcard vs subdomain (overlap)
test_ingress_wildcard_vs_subdomain_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_ingress
	count(res) == 1
}

# REJECT: subdomain vs wildcard (overlap)
test_ingress_subdomain_vs_wildcard_rejected if {
	res := violation with input as review_ingress_subdomain with data.inventory as inventory_wildcard
	count(res) == 1
}

# ALLOW: wildcard vs base domain
test_ingress_wildcard_vs_base_allowed if {
	base := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-base": {
		"metadata": {"name": "ing-base", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}}}
	res := violation with input as review_ingress_wildcard with data.inventory as base
	count(res) == 0
}

# =============================================================================
# GATEWAY TESTS
# =============================================================================

inventory_gateway := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-existing": {
	"metadata": {"name": "gw-existing", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "app.example.com"}]},
}}}}}}

inventory_gateway_wildcard := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-wc": {
	"metadata": {"name": "gw-wc", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "*.example.com"}]},
}}}}}}

# REJECT: Ingress vs Gateway exact match
test_ingress_vs_gateway_rejected if {
	res := violation with input as review_ingress_subdomain with data.inventory as inventory_gateway
	count(res) == 1
}

# REJECT: Ingress vs Gateway wildcard overlap
test_ingress_vs_gateway_wildcard_rejected if {
	res := violation with input as review_ingress_subdomain with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

# ALLOW: Ingress vs Gateway different host
test_ingress_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_ingress_subdomain with data.inventory as diff
	count(res) == 0
}

# =============================================================================
# HTTPROUTE TESTS
# =============================================================================

inventory_httproute := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-existing": {
	"metadata": {"name": "hr-existing", "namespace": "tenant-a"},
	"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
}}}}}}

inventory_httproute_wildcard := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-wc": {
	"metadata": {"name": "hr-wc", "namespace": "tenant-a"},
	"spec": {"hostnames": ["*.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
}}}}}}

# REJECT: Ingress vs HTTPRoute exact match
test_ingress_vs_httproute_rejected if {
	res := violation with input as review_ingress_subdomain with data.inventory as inventory_httproute
	count(res) == 1
}

# REJECT: Ingress vs HTTPRoute wildcard overlap
test_ingress_vs_httproute_wildcard_rejected if {
	res := violation with input as review_ingress_subdomain with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

# ALLOW: Ingress vs HTTPRoute different host
test_ingress_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_ingress_subdomain with data.inventory as diff
	count(res) == 0
}

# ALLOW: Ingress vs HTTPRoute same host, different path
test_ingress_vs_httproute_diff_path_allowed if {
	diff_path := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-apath": {
		"metadata": {"name": "hr-apath", "namespace": "tenant-a"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
	}}}}}}
	res := violation with input as review_ingress_subdomain with data.inventory as diff_path
	count(res) == 0
}

# =============================================================================
# GATEWAY INPUT TESTS
# =============================================================================

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

# REJECT: Gateway vs Ingress
test_gateway_vs_ingress_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_ingress
	count(res) == 1
}

# REJECT: Gateway vs Gateway
test_gateway_vs_gateway_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_gateway
	count(res) == 1
}

# REJECT: Gateway vs HTTPRoute
test_gateway_vs_httproute_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_httproute
	count(res) == 1
}

# ALLOW: Gateway vs Ingress different host
test_gateway_vs_ingress_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-other": {
		"metadata": {"name": "ing-other", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}}}
	res := violation with input as review_gateway with data.inventory as diff
	count(res) == 0
}

# ALLOW: Gateway vs Gateway different host
test_gateway_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_gateway with data.inventory as diff
	count(res) == 0
}

# ALLOW: Gateway vs HTTPRoute different host
test_gateway_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_gateway with data.inventory as diff
	count(res) == 0
}

# =============================================================================
# HTTPROUTE INPUT TESTS
# =============================================================================

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

# REJECT: HTTPRoute vs Ingress
test_httproute_vs_ingress_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_ingress
	count(res) == 1
}

# REJECT: HTTPRoute vs Gateway
test_httproute_vs_gateway_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_gateway
	count(res) == 1
}

# REJECT: HTTPRoute vs HTTPRoute
test_httproute_vs_httproute_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_httproute
	count(res) == 1
}

# ALLOW: HTTPRoute vs Ingress different host
test_httproute_vs_ingress_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-other": {
		"metadata": {"name": "ing-other", "namespace": "tenant-a"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff
	count(res) == 0
}

# ALLOW: HTTPRoute vs Gateway different host
test_httproute_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff
	count(res) == 0
}

# ALLOW: HTTPRoute vs HTTPRoute different host
test_httproute_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff
	count(res) == 0
}

# ALLOW: HTTPRoute vs HTTPRoute same host, different path
test_httproute_vs_httproute_diff_path_allowed if {
	diff_path := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-apath": {
		"metadata": {"name": "hr-apath", "namespace": "tenant-a"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff_path
	count(res) == 0
}
