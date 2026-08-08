# Multi-Gateway Policy - Detects hostname conflicts across Ingress, Gateway, and HTTPRoute
# Extended from the unique-ingress-host policy

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

# ============================================
# Ingress vs Ingress (existing functionality)
# ============================================
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
	msg := sprintf("ingress host <%v%v> conflicts with an existing ingress", [host, path])
}

# ============================================
# Ingress vs Gateway
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
	ingress_host := input.review.object.spec.rules[_].host
	ingress_path := input.review.object.spec.rules[_].http.paths[_].path

	gateway := data.inventory.namespace[_]["gateway.networking.k8s.io/v1"].Gateway[name]
	gateway_hostname := gateway.spec.listeners[_].hostname

	host_conflict(ingress_host, gateway_hostname)
	not identical(gateway, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with a Gateway listener hostname <%v>", [ingress_host, ingress_path, gateway_hostname])
}

# ============================================
# Ingress vs HTTPRoute
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
	ingress_host := input.review.object.spec.rules[_].host
	ingress_path := input.review.object.spec.rules[_].http.paths[_].path

	route := data.inventory.namespace[_]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	route_hostname := route.spec.hostnames[_]
	rule := route.spec.rules[_]
	match_obj := rule.matches[_]
	route_path := match_obj.path.value

	host_conflict(ingress_host, route_hostname)
	ingress_path == route_path
	not identical(route, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with an HTTPRoute host <%v>", [ingress_host, ingress_path, route_hostname])
}

# ============================================
# Gateway vs Ingress
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	gateway_host := input.review.object.spec.listeners[_].hostname
	ingress := data.inventory.namespace[_][version].Ingress[name]
	ingress_host := ingress.spec.rules[_].host

	host_conflict(gateway_host, ingress_host)
	not identical(ingress, input.review)
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing Ingress host <%v>", [gateway_host, ingress_host])
}

# ============================================
# Gateway vs Gateway
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	gateway_host := input.review.object.spec.listeners[_].hostname
	other := data.inventory.namespace[_]["gateway.networking.k8s.io/v1"].Gateway[name]
	other_host := other.spec.listeners[_].hostname

	host_conflict(gateway_host, other_host)
	not identical(other, input.review)
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing Gateway listener hostname <%v>", [gateway_host, other_host])
}

# ============================================
# Gateway vs HTTPRoute
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	gateway_host := input.review.object.spec.listeners[_].hostname
	route := data.inventory.namespace[_]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	route_hostname := route.spec.hostnames[_]

	host_conflict(gateway_host, route_hostname)
	not identical(route, input.review)
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing HTTPRoute host <%v>", [gateway_host, route_hostname])
}

# ============================================
# HTTPRoute vs Ingress
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	route_host := input.review.object.spec.hostnames[_]
	rule := input.review.object.spec.rules[_]
	match_obj := rule.matches[_]
	route_path := match_obj.path.value

	ingress := data.inventory.namespace[_][version].Ingress[name]
	ingress_host := ingress.spec.rules[_].host
	ingress_path := ingress.spec.rules[_].http.paths[_].path

	host_conflict(route_host, ingress_host)
	route_path == ingress_path
	not identical(ingress, input.review)
	msg := sprintf("HTTPRoute host <%v%v> conflicts with an existing Ingress host <%v>", [route_host, route_path, ingress_host])
}

# ============================================
# HTTPRoute vs Gateway
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	route_host := input.review.object.spec.hostnames[_]
	gateway := data.inventory.namespace[_]["gateway.networking.k8s.io/v1"].Gateway[name]
	gateway_host := gateway.spec.listeners[_].hostname

	host_conflict(route_host, gateway_host)
	not identical(gateway, input.review)
	msg := sprintf("HTTPRoute host <%v> conflicts with an existing Gateway listener hostname <%v>", [route_host, gateway_host])
}

# ============================================
# HTTPRoute vs HTTPRoute
# ============================================
violation[{"msg": msg}] {
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	route_host := input.review.object.spec.hostnames[_]
	rule := input.review.object.spec.rules[_]
	match_obj := rule.matches[_]
	route_path := match_obj.path.value

	other := data.inventory.namespace[_]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	other_host := other.spec.hostnames[_]
	other_rule := other.spec.rules[_]
	other_match := other_rule.matches[_]
	other_path := other_match.path.value

	host_conflict(route_host, other_host)
	route_path == other_path
	not identical(other, input.review)
	msg := sprintf("HTTPRoute host <%v%v> conflicts with an existing HTTPRoute host <%v>", [route_host, route_path, other_host])
}
