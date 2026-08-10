# Taken from https://open-policy-agent.github.io/gatekeeper-library/website/validation/uniqueingresshost/
# Extended to support wildcard hostnames and path-based conflict detection

package policy

# Helper: Check if two objects are the same (same namespace and name)
identical(obj, review) := true {
	obj.metadata.namespace == review.object.metadata.namespace
	obj.metadata.name == review.object.metadata.name
}

# Host conflict: exact match or wildcard overlap
host_conflict(host1, host2) := true {
	host1 == host2
}

host_conflict(host1, host2) := true {
	startswith(host1, "*.")
	not startswith(host2, "*.")
	wildcard_domain := trim_prefix(host1, "*.")
	endswith(host2, wildcard_domain)
	parts := split(host2, ".")
	wc_parts := split(wildcard_domain, ".")
	count(parts) == count(wc_parts) + 1
}

host_conflict(host1, host2) := true {
	startswith(host2, "*.")
	not startswith(host1, "*.")
	wildcard_domain := trim_prefix(host2, "*.")
	endswith(host1, wildcard_domain)
	parts := split(host1, ".")
	wc_parts := split(wildcard_domain, ".")
	count(parts) == count(wc_parts) + 1
}

violation[{"msg": msg}] {
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
	host := input.review.object.spec.rules[_].host
	path := input.review.object.spec.rules[_].http.paths[_].path
	other := data.inventory.namespace[_][otherapiversion].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", otherapiversion)
	other_host := other.spec.rules[_].host
	other_path := other.spec.rules[_].http.paths[_].path
	host_conflict(host, other_host)
	path == other_path
	not identical(other, input.review)
	msg := sprintf("ingress host conflicts with an existing ingress <%v%v>", [host, path])
}
