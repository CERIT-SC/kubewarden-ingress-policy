package policy

# ============================================
# Existing inventory for testing
# ============================================
inventory_ingress = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"ing-existing": {
	"metadata": {"name": "ing-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

inventory_gateway = {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-existing": {
	"metadata": {"name": "gw-existing", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "app.example.com"}]},
}}}}}}

inventory_httproute = {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-existing": {
	"metadata": {"name": "hr-existing", "namespace": "tenant-a"},
	"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
}}}}}}

# ============================================
# --- INGRESS test cases ---
# ============================================

# Test: Ingress vs Ingress - exact match should be denied
review_ingress_same = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_ingress_vs_ingress_rejected {
	r = review_ingress_same
	res = violation with input as r with data.inventory as inventory_ingress
	count(res) == 1
}

# Test: Ingress vs Gateway - should be denied
review_ingress_vs_gw = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_ingress_vs_gateway_rejected {
	r = review_ingress_vs_gw
	res = violation with input as r with data.inventory as inventory_gateway
	count(res) == 1
}

# Test: Ingress vs HTTPRoute - should be denied
review_ingress_vs_hr = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_ingress_vs_httproute_rejected {
	r = review_ingress_vs_hr
	res = violation with input as r with data.inventory as inventory_httproute
	count(res) == 1
}

# Test: Ingress allowed - different host
review_ingress_diff = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_ingress_different_host_allowed {
	r = review_ingress_diff
	res = violation with input as r with data.inventory as inventory_ingress
	count(res) == 0
}

# Test: Ingress allowed - same host, different path
review_ingress_diff_path = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
	},
}}

test_ingress_same_host_diff_path_allowed {
	r = review_ingress_diff_path
	res = violation with input as r with data.inventory as inventory_ingress
	count(res) == 0
}

# ============================================
# --- GATEWAY test cases ---
# ============================================

# Test: Gateway vs Ingress - should be denied
review_gateway_vs_ing = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"listeners": [{"hostname": "app.example.com"}]},
	},
}}

test_gateway_vs_ingress_rejected {
	r = review_gateway_vs_ing
	res = violation with input as r with data.inventory as inventory_ingress
	count(res) == 1
}

# Test: Gateway vs Gateway - exact match should be denied
inventory_gateway_same = {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-existing2": {
	"metadata": {"name": "gw-existing2", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "app.example.com"}]},
}}}}}}

review_gateway_same = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"listeners": [{"hostname": "app.example.com"}]},
	},
}}

test_gateway_vs_gateway_rejected {
	r = review_gateway_same
	res = violation with input as r with data.inventory as inventory_gateway_same
	count(res) == 1
}

# Test: Gateway vs HTTPRoute - should be denied
review_gateway_vs_hr = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"listeners": [{"hostname": "app.example.com"}]},
	},
}}

test_gateway_vs_httproute_rejected {
	r = review_gateway_vs_hr
	res = violation with input as r with data.inventory as inventory_httproute
	count(res) == 1
}

# Test: Gateway allowed - different host
review_gateway_diff = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "Gateway"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"listeners": [{"hostname": "other.example.com"}]},
	},
}}

test_gateway_different_host_allowed {
	r = review_gateway_diff
	res = violation with input as r with data.inventory as inventory_gateway
	count(res) == 0
}

# ============================================
# --- HTTPROUTE test cases ---
# ============================================

# Test: HTTPRoute vs Ingress - should be denied
review_httproute_vs_ing = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

test_httproute_vs_ingress_rejected {
	r = review_httproute_vs_ing
	res = violation with input as r with data.inventory as inventory_ingress
	count(res) == 1
}

# Test: HTTPRoute vs Gateway - should be denied
review_httproute_vs_gw = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

test_httproute_vs_gateway_rejected {
	r = review_httproute_vs_gw
	res = violation with input as r with data.inventory as inventory_gateway
	count(res) == 1
}

# Test: HTTPRoute vs HTTPRoute - exact match should be denied
inventory_httproute_same = {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"HTTPRoute": {"hr-existing2": {
	"metadata": {"name": "hr-existing2", "namespace": "tenant-a"},
	"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
}}}}}}

review_httproute_same = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

test_httproute_vs_httproute_rejected {
	r = review_httproute_same
	res = violation with input as r with data.inventory as inventory_httproute_same
	count(res) == 1
}

# Test: HTTPRoute allowed - different host
review_httproute_diff = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["other.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

test_httproute_different_host_allowed {
	r = review_httproute_diff
	res = violation with input as r with data.inventory as inventory_httproute
	count(res) == 0
}

# Test: HTTPRoute allowed - same host, different path
review_httproute_diff_path = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/api"}}]}]},
	},
}}

test_httproute_same_host_diff_path_allowed {
	r = review_httproute_diff_path
	res = violation with input as r with data.inventory as inventory_httproute
	count(res) == 0
}

# ============================================
# --- WILDCARD test cases ---
# ============================================

inventory_wildcard = {"namespace": {"tenant-a": {"gateway.networking.k8s.io/v1": {"Gateway": {"gw-wc": {
	"metadata": {"name": "gw-wc", "namespace": "tenant-a"},
	"spec": {"listeners": [{"hostname": "*.example.com"}]},
}}}}}}

# Test: Wildcard Gateway vs Ingress subdomain - should be denied
review_ingress_wc_overlap = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_wildcard_gateway_vs_ingress_rejected {
	r = review_ingress_wc_overlap
	res = violation with input as r with data.inventory as inventory_wildcard
	count(res) == 1
}

# Test: Wildcard Gateway vs HTTPRoute subdomain - should be denied
review_httproute_wc_overlap = {"review": {
	"kind": {"group": "gateway.networking.k8s.io", "version": "v1", "kind": "HTTPRoute"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"hostnames": ["app.example.com"], "rules": [{"matches": [{"path": {"value": "/"}}]}]},
	},
}}

test_wildcard_gateway_vs_httproute_rejected {
	r = review_httproute_wc_overlap
	res = violation with input as r with data.inventory as inventory_wildcard
	count(res) == 1
}
