package policy

# ============================================
# Existing inventory (namespace tenant-a)
# ============================================
inventory = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"existing": {
	"metadata": {"name": "existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

# ============================================
# --- REJECT test cases (should have violations) ---
# ============================================

# Test 1: same-host - exact match should be denied
review_same_host = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_same_host_rejected {
	r = review_same_host
	res = violation with input as r with data.inventory as inventory
	count(res) == 1
}

# Test 2: wildcard-same - identical wildcards should be denied
inventory_wildcard = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"wc-existing": {
	"metadata": {"name": "wc-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

review_wildcard_same = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_wildcard_same_rejected {
	r = review_wildcard_same
	res = violation with input as r with data.inventory as inventory_wildcard
	count(res) == 1
}

# Test 3: wildcard-overlap - wildcard *.example.com conflicts with app.example.com
review_wildcard_overlap = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "*.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_wildcard_overlap_rejected {
	r = review_wildcard_overlap
	res = violation with input as r with data.inventory as inventory
	count(res) == 1
}

# Test 4: wildcard-sub - wildcard *.foo.example.com conflicts with app.foo.example.com
inventory_wildcard_sub = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"wc-sub-existing": {
	"metadata": {"name": "wc-sub-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "*.foo.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

review_wildcard_sub = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "*.foo.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_wildcard_sub_rejected {
	r = review_wildcard_sub
	res = violation with input as r with data.inventory as inventory_wildcard_sub
	count(res) == 1
}

# ============================================
# --- ALLOW test cases (should have NO violations) ---
# ============================================

# Test 5: wildcard-host - exact domain example.com does NOT conflict with wildcard *.example.com
# (wildcard is for subdomains only, not the base domain itself)
review_wildcard_host = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_wildcard_host_allowed {
	r = review_wildcard_host
	res = violation with input as r with data.inventory as inventory_wildcard
	count(res) == 0
}

# Test 6: wildcard-diff - different wildcards do not conflict
inventory_wildcard_diff = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"wc-diff-existing": {
	"metadata": {"name": "wc-diff-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "*.app.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

review_wildcard_diff = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "*.other.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_wildcard_diff_allowed {
	r = review_wildcard_diff
	res = violation with input as r with data.inventory as inventory_wildcard_diff
	count(res) == 0
}

# Test 7: same-host-diff-path - same host with different paths should be allowed
review_same_host_diff_path = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/a"}]}}]},
	},
}}

test_same_host_diff_path_allowed {
	r = review_same_host_diff_path
	res = violation with input as r with data.inventory as inventory
	count(res) == 0
}

# Test 8: same-host-with-sub - exact host app.example.com does NOT conflict with subdomain sub.app.example.com
inventory_exact = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"exact-existing": {
	"metadata": {"name": "exact-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

review_same_host_with_sub = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "sub.app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_same_host_with_sub_allowed {
	r = review_same_host_with_sub
	res = violation with input as r with data.inventory as inventory_exact
	count(res) == 0
}

# Test 9: diff-host - different hosts do not conflict
inventory_other = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"other-existing": {
	"metadata": {"name": "other-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/"}]}}]},
}}}}}}

review_diff_host = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/"}]}}]},
	},
}}

test_diff_host_allowed {
	r = review_diff_host
	res = violation with input as r with data.inventory as inventory_other
	count(res) == 0
}

# Test 10: diff-host-same-path - different hosts with same path do not conflict
review_diff_host_same_path = {"review": {
	"kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
	"object": {
		"metadata": {"namespace": "default", "name": "test"},
		"spec": {"rules": [{"host": "other.example.com", "http": {"paths": [{"path": "/api"}]}}]},
	},
}}

inventory_api = {"namespace": {"tenant-a": {"networking.k8s.io/v1": {"Ingress": {"api-existing": {
	"metadata": {"name": "api-existing", "namespace": "tenant-a"},
	"spec": {"rules": [{"host": "app.example.com", "http": {"paths": [{"path": "/api"}]}}]},
}}}}}}

test_diff_host_same_path_allowed {
	r = review_diff_host_same_path
	res = violation with input as r with data.inventory as inventory_api
	count(res) == 0
}
