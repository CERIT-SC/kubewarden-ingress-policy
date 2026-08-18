package policy

import rego.v1

# Check if two objects are the same (same namespace and name)
same_object(ns, name, review) := true if {
	ns == review.object.metadata.namespace
	name == review.object.metadata.name
}

# Host conflict: exact match or wildcard overlap (same depth only)
host_conflict(host1, host2) := true if {
	host1 == host2
} else := true if {
	startswith(host1, "*.")
	not startswith(host2, "*.")
	endswith(host2, trim_prefix(host1, "*."))
	count(split(host2, ".")) == count(split(trim_prefix(host1, "*."), ".")) + 1
} else := true if {
	startswith(host2, "*.")
	not startswith(host1, "*.")
	endswith(host1, trim_prefix(host2, "*."))
	count(split(host1, ".")) == count(split(trim_prefix(host2, "*."), ".")) + 1
} else := false

# =============================================================================
# Ingress vs Ingress
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is Ingress
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)

	# Get input host and path
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path

	# Iterate over existing ingresses in inventory
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)

	# Get inventory ingress host and path
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path

	# Check for conflict (same host and path, different object)
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("ingress host <%v%v> conflicts with an existing ingress", [inp_host, inp_path])
}

# =============================================================================
# Ingress vs Gateway
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is Ingress
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)

	# Get input host and path
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path

	# Iterate over existing Gateways in inventory
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]

	# Get inventory gateway hostname (no paths for Gateway)
	inv_host := gw.spec.listeners[_].hostname

	# Check for conflict (same host, different object)
	# Note: Gateway has no paths, so any host conflict is a violation
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("ingress host <%v%v> conflicts with a Gateway listener hostname <%v>", [inp_host, inp_path, inv_host])
}

# =============================================================================
# Ingress vs HTTPRoute
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is Ingress
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)

	# Get input host and path
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path

	# Iterate over existing HTTPRoutes in inventory
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]

	# Get inventory httproute host and path
	inv_host := hr.spec.hostnames[_]
	inv_rule := hr.spec.rules[_]
	inv_match := inv_rule.matches[_]
	inv_path := inv_match.path.value

	# Check for conflict (same host and path, different object)
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("ingress host <%v%v> conflicts with an HTTPRoute host <%v>", [inp_host, inp_path, inv_host])
}

# =============================================================================
# Gateway vs Ingress
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is Gateway
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	# Get input hostname (no paths for Gateway)
	inp_host := input.review.object.spec.listeners[_].hostname
	inp_path := ""

	# Iterate over existing ingresses in inventory
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)

	# Get inventory ingress host and path
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path

	# Check for conflict (Gateway has no paths, so any host conflict is violation)
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing Ingress host <%v>", [inp_host, inv_host])
}

# =============================================================================
# Gateway vs Gateway
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is Gateway
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	# Get input hostname
	inp_host := input.review.object.spec.listeners[_].hostname
	inp_path := ""

	# Iterate over existing Gateways in inventory
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]

	# Get inventory gateway hostname
	inv_host := gw.spec.listeners[_].hostname

	# Check for conflict
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing Gateway listener hostname <%v>", [inp_host, inv_host])
}

# =============================================================================
# Gateway vs HTTPRoute
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is Gateway
	input.review.kind.kind == "Gateway"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	# Get input hostname
	inp_host := input.review.object.spec.listeners[_].hostname
	inp_path := ""

	# Iterate over existing HTTPRoutes in inventory
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]

	# Get inventory httproute host and path
	inv_host := hr.spec.hostnames[_]
	inv_rule := hr.spec.rules[_]
	inv_match := inv_rule.matches[_]
	inv_path := inv_match.path.value

	# Check for conflict (Gateway has no paths)
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("Gateway listener hostname <%v> conflicts with an existing HTTPRoute host <%v>", [inp_host, inv_host])
}

# =============================================================================
# HTTPRoute vs Ingress
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is HTTPRoute
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	# Get input host and path
	inp_host := input.review.object.spec.hostnames[_]
	inp_rule := input.review.object.spec.rules[_]
	inp_match := inp_rule.matches[_]
	inp_path := inp_match.path.value

	# Iterate over existing ingresses in inventory
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)

	# Get inventory ingress host and path
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path

	# Check for conflict (same host and path, different object)
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("HTTPRoute host <%v%v> conflicts with an existing Ingress host <%v>", [inp_host, inp_path, inv_host])
}

# =============================================================================
# HTTPRoute vs Gateway
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is HTTPRoute
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	# Get input host and path
	inp_host := input.review.object.spec.hostnames[_]
	inp_rule := input.review.object.spec.rules[_]
	inp_match := inp_rule.matches[_]
	inp_path := inp_match.path.value

	# Iterate over existing Gateways in inventory
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]

	# Get inventory gateway hostname
	inv_host := gw.spec.listeners[_].hostname

	# Check for conflict (Gateway has no paths)
	host_conflict(inp_host, inv_host)
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("HTTPRoute host <%v> conflicts with an existing Gateway listener hostname <%v>", [inp_host, inv_host])
}

# =============================================================================
# HTTPRoute vs HTTPRoute
# =============================================================================

violation contains {"msg": msg} if {
	# Check input is HTTPRoute
	input.review.kind.kind == "HTTPRoute"
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"

	# Get input host and path
	inp_host := input.review.object.spec.hostnames[_]
	inp_rule := input.review.object.spec.rules[_]
	inp_match := inp_rule.matches[_]
	inp_path := inp_match.path.value

	# Iterate over existing HTTPRoutes in inventory
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]

	# Get inventory httproute host and path
	inv_host := hr.spec.hostnames[_]
	inv_rule := hr.spec.rules[_]
	inv_match := inv_rule.matches[_]
	inv_path := inv_match.path.value

	# Check for conflict (same host and path, different object)
	host_conflict(inp_host, inv_host)
	inp_path == inv_path
	not same_object(ns, name, input.review)

	# Build message
	msg := sprintf("HTTPRoute host <%v%v> conflicts with an existing HTTPRoute host <%v>", [inp_host, inp_path, inv_host])
}
