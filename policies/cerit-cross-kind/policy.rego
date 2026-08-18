package policy

import rego.v1

# =============================================================================
# HELPERS
# =============================================================================

same_object(ns, name, review) := true if {
	ns == review.object.metadata.namespace
	name == review.object.metadata.name
}

host_conflict(host1, host2) := true if {
	host1 == host2
} else := true if {
	startswith(host1, "*.")
	not startswith(host2, "*.")
	endswith(host2, trim_prefix(host1, "*."))
	count(split(host2, ".")) > count(split(trim_prefix(host1, "*."), "."))
} else := true if {
	startswith(host2, "*.")
	not startswith(host1, "*.")
	endswith(host1, trim_prefix(host2, "*."))
	count(split(host1, ".")) > count(split(trim_prefix(host2, "*."), "."))
} else := false

# =============================================================================
# KIND DETECTION
# =============================================================================

input_is_ingress := true if {
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
}

input_is_gateway := true if {
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"
}

input_is_httproute := true if {
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"
}

# =============================================================================
# VIOLATION RULES
# =============================================================================

# Ingress vs Ingress
violation contains {"msg": msg} if {
	input_is_ingress
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with an existing ingress", [inp_host, inp_path])
}

# Ingress vs Gateway
violation contains {"msg": msg} if {
	input_is_ingress
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]
	inv_host := gw.spec.listeners[_].hostname
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with a Gateway listener hostname <%v>", [inp_host, inp_path, inv_host])
}

# Ingress vs HTTPRoute
violation contains {"msg": msg} if {
	input_is_ingress
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	inv_host := hr.spec.hostnames[_]
	inv_rule := hr.spec.rules[_]
	inv_match := inv_rule.matches[_]
	inv_path := inv_match.path.value
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with an HTTPRoute host <%v>", [inp_host, inp_path, inv_host])
}

# Gateway vs Ingress
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)
	inv_host := other.spec.rules[_].host
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing Ingress host <%v>", [inp_host, inv_host])
}

# Gateway vs Gateway
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]
	inv_host := gw.spec.listeners[_].hostname
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing Gateway listener hostname <%v>", [inp_host, inv_host])
}

# Gateway vs HTTPRoute
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	inv_host := hr.spec.hostnames[_]
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing HTTPRoute host <%v>", [inp_host, inv_host])
}

# HTTPRoute vs Ingress
violation contains {"msg": msg} if {
	input_is_httproute
	inp_host := input.review.object.spec.hostnames[_]
	inp_rule := input.review.object.spec.rules[_]
	inp_match := inp_rule.matches[_]
	inp_path := inp_match.path.value
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)
	msg := sprintf("HTTPRoute host <%v%v> conflicts with an existing Ingress host <%v>", [inp_host, inp_path, inv_host])
}

# HTTPRoute vs Gateway
violation contains {"msg": msg} if {
	input_is_httproute
	inp_host := input.review.object.spec.hostnames[_]
	inp_rule := input.review.object.spec.rules[_]
	inp_match := inp_rule.matches[_]
	inp_path := inp_match.path.value
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]
	inv_host := gw.spec.listeners[_].hostname
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)
	msg := sprintf("HTTPRoute host <%v> conflicts with an existing Gateway listener hostname <%v>", [inp_host, inv_host])
}

# HTTPRoute vs HTTPRoute
violation contains {"msg": msg} if {
	input_is_httproute
	inp_host := input.review.object.spec.hostnames[_]
	inp_rule := input.review.object.spec.rules[_]
	inp_match := inp_rule.matches[_]
	inp_path := inp_match.path.value
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	inv_host := hr.spec.hostnames[_]
	inv_rule := hr.spec.rules[_]
	inv_match := inv_rule.matches[_]
	inv_path := inv_match.path.value
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)
	msg := sprintf("HTTPRoute host <%v%v> conflicts with an existing HTTPRoute host <%v>", [inp_host, inp_path, inv_host])
}
