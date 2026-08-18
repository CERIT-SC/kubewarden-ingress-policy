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

inventory_base := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-base": {
	"metadata": {"name": "ing-base", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

inventory_diff_host := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-other": {
	"metadata": {"name": "ing-other", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

inventory_diff_path := {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-apath": {
	"metadata": {"name": "ing-apath", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
}}}}}}

inventory_httproute_diff_path := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-apath": {
	"metadata": {"name": "hr-apath", "namespace": "tenant-a"},
	"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
}}}}}}

# Multi-level subdomain input (for testing wildcard overlap at any depth)
review_ingress_multi_sub := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "sub.app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

review_httproute_multi_sub := {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["sub.app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

# =============================================================================
# INPUTS
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

review_ingress_diff_path := {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
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
# TEST CASES - Ingress input
# =============================================================================

test_ingress_vs_ingress_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress
	count(res) == 1
}

test_ingress_different_host_allowed if {
	res := violation with input as review_ingress_diff_host with data.inventory as inventory_ingress
	count(res) == 0
}

test_ingress_same_host_diff_path_allowed if {
	res := violation with input as review_ingress_diff_path with data.inventory as inventory_ingress
	count(res) == 0
}

test_ingress_wildcard_vs_subdomain_rejected if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_ingress
	count(res) == 1
}

test_ingress_subdomain_vs_wildcard_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_ingress_wildcard_vs_base_allowed if {
	res := violation with input as review_ingress_wildcard with data.inventory as inventory_base
	count(res) == 0
}

# REJECT: multi-level subdomain vs wildcard (deeper overlap)
test_ingress_multi_sub_vs_wildcard_rejected if {
	res := violation with input as review_ingress_multi_sub with data.inventory as inventory_ingress_wildcard
	count(res) == 1
}

test_ingress_vs_gateway_multi_sub_rejected if {
	res := violation with input as review_ingress_multi_sub with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_ingress_vs_httproute_multi_sub_rejected if {
	res := violation with input as review_ingress_multi_sub with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

test_httproute_multi_sub_vs_wildcard_rejected if {
	res := violation with input as review_httproute_multi_sub with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

test_httproute_multi_sub_vs_gateway_rejected if {
	res := violation with input as review_httproute_multi_sub with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_ingress_vs_gateway_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_gateway
	count(res) == 1
}

test_ingress_vs_gateway_wildcard_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_gateway_wildcard
	count(res) == 1
}

test_ingress_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_ingress with data.inventory as diff
	count(res) == 0
}

test_ingress_vs_httproute_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_httproute
	count(res) == 1
}

test_ingress_vs_httproute_wildcard_rejected if {
	res := violation with input as review_ingress with data.inventory as inventory_httproute_wildcard
	count(res) == 1
}

test_ingress_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_ingress with data.inventory as diff
	count(res) == 0
}

test_ingress_vs_httproute_diff_path_allowed if {
	res := violation with input as review_ingress with data.inventory as inventory_httproute_diff_path
	count(res) == 0
}

# =============================================================================
# TEST CASES - Gateway input
# =============================================================================

test_gateway_vs_ingress_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_ingress
	count(res) == 1
}

test_gateway_vs_gateway_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_gateway
	count(res) == 1
}

test_gateway_vs_httproute_rejected if {
	res := violation with input as review_gateway with data.inventory as inventory_httproute
	count(res) == 1
}

test_gateway_vs_ingress_diff_host_allowed if {
	res := violation with input as review_gateway with data.inventory as inventory_diff_host
	count(res) == 0
}

test_gateway_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_gateway with data.inventory as diff
	count(res) == 0
}

test_gateway_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_gateway with data.inventory as diff
	count(res) == 0
}

# =============================================================================
# TEST CASES - HTTPRoute input
# =============================================================================

test_httproute_vs_ingress_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_ingress
	count(res) == 1
}

test_httproute_vs_gateway_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_gateway
	count(res) == 1
}

test_httproute_vs_httproute_rejected if {
	res := violation with input as review_httproute with data.inventory as inventory_httproute
	count(res) == 1
}

test_httproute_vs_ingress_diff_host_allowed if {
	res := violation with input as review_httproute with data.inventory as inventory_diff_host
	count(res) == 0
}

test_httproute_vs_gateway_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-other": {
		"metadata": {"name": "gw-other", "namespace": "tenant-a"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff
	count(res) == 0
}

test_httproute_vs_httproute_diff_host_allowed if {
	diff := {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-other": {
		"metadata": {"name": "hr-other", "namespace": "tenant-a"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	}}}}}}
	res := violation with input as review_httproute with data.inventory as diff
	count(res) == 0
}

test_httproute_vs_httproute_diff_path_allowed if {
	res := violation with input as review_httproute_diff_path with data.inventory as inventory_httproute
	count(res) == 0
}
