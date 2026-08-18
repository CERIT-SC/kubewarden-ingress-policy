# Detects hostname conflicts among Ingress resources
# Supports wildcard hostnames and path-based conflict detection

package policy

import rego.v1

# Check if two objects are the same (same namespace and name)
identical(obj, review) := true if {
	obj.metadata.namespace == review.object.metadata.namespace
	obj.metadata.name == review.object.metadata.name
}

# Host conflict: exact match or wildcard overlap
# *.example.com matches app.example.com AND sub.app.example.com (any depth)
host_conflict(host1, host2) := true if {
	host1 == host2
} else := true if {
	startswith(host1, "*.")
	endswith(host2, trim_prefix(host1, "*."))
	count(split(host2, ".")) > count(split(trim_prefix(host1, "*."), "."))
} else := true if {
	startswith(host2, "*.")
	endswith(host1, trim_prefix(host2, "*."))
	count(split(host1, ".")) > count(split(trim_prefix(host2, "*."), "."))
} else := false

# Violation: detect conflicting ingress hosts on the same path
violation contains {"msg": msg} if {
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)

	host := input.review.object.spec.rules[_].host
	path := input.review.object.spec.rules[_].http.paths[_].path

	other := data.inventory.namespace[_][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)

	other_host := other.spec.rules[_].host
	other_path := other.spec.rules[_].http.paths[_].path

	host_conflict(host, other_host)
	path == other_path
	not identical(other, input.review)

	msg := sprintf("ingress host conflicts with an existing ingress <%v%v>", [host, path])
}
