package policy

import rego.v1

# =============================================================================
# KIND DETECTION
# =============================================================================

input_is_ingress := true if {
	input.review.kind.kind == "Ingress"
	regex.match("^(extensions|networking.k8s.io)$", input.review.kind.group)
}

input_is_gateway := true if {
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"
	input.review.kind.kind == "Gateway"
}

input_is_httproute := true if {
	input.review.kind.group == "gateway.networking.k8s.io"
	input.review.kind.version == "v1"
	input.review.kind.kind == "HTTPRoute"
}

input_is_traefik_ingressroute := true if {
	input.review.kind.group == "traefik.io"
	input.review.kind.version == "v1alpha1"
	input.review.kind.kind == "IngressRoute"
}

# =============================================================================
# TRAEFIK MATCH EXPRESSION PARSING
# =============================================================================

# Extract all hosts from Traefik match expressions
# Pattern: Host(`value`)
traefik_host_pattern := "Host\\(`([^`]+)`\\)"

input_traefik_hosts[host] if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	host := matches[_][1]
}

# Extract all paths from Traefik match expressions
# Pattern: Path(`value`) or PathPrefix(`value`)
traefik_path_pattern := "Path(?:Prefix)?\\(`([^`]+)`\\)"

input_traefik_paths[path] if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_path_pattern, route.match, -1)
	path := matches[_][1]
}

# If no path specified, treat as "all paths" (empty string)
input_traefik_paths[""] if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	not regex.match(traefik_path_pattern, route.match)
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Host conflict detection with wildcard and multi-level subdomain support
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

# Path overlap detection
path_overlap(p1, p2) := true if {
	p1 == p2
} else := true if {
	p1 == ""
} else := true if {
	p2 == ""
} else := true if {
	startswith(p2, p1)
} else := false

# Same object check
same_object(ns1, name1, review) if {
	review.object.metadata.namespace == ns1
	review.object.metadata.name == name1
}

# Skip same namespace (allow conflicts within namespace)
skip_same_namespace(ns1, review) if {
	review.object.metadata.namespace == ns1
}

# =============================================================================
# VIOLATION RULES - Standard kinds (Ingress, Gateway, HTTPRoute)
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
	not skip_same_namespace(ns, input.review)
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
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with a gateway listener hostname <%v>", [inp_host, inp_path, inv_host])
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
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with an httproute host <%v>", [inp_host, inp_path, inv_host])
}

# Gateway vs Ingress
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	other := data.inventory.namespace[ns][api_version].Ingress[name]
	regex.match("^(extensions|networking.k8s.io)/.+$", api_version)
	inv_host := other.spec.rules[_].host
	host_conflict(inp_host, inv_host)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("gateway listener hostname <%v> conflicts with an existing ingress host <%v>", [inp_host, inv_host])
}

# Gateway vs Gateway
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]
	inv_host := gw.spec.listeners[_].hostname
	host_conflict(inp_host, inv_host)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("gateway listener hostname <%v> conflicts with an existing gateway listener hostname <%v>", [inp_host, inv_host])
}

# Gateway vs HTTPRoute
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	hr := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	inv_host := hr.spec.hostnames[_]
	host_conflict(inp_host, inv_host)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("gateway listener hostname <%v> conflicts with an existing httproute host <%v>", [inp_host, inv_host])
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
	not skip_same_namespace(ns, input.review)
	msg := sprintf("httproute host <%v%v> conflicts with an existing ingress host <%v>", [inp_host, inp_path, inv_host])
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
	not skip_same_namespace(ns, input.review)
	msg := sprintf("httproute host <%v> conflicts with an existing gateway listener hostname <%v>", [inp_host, inv_host])
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
	not skip_same_namespace(ns, input.review)
	msg := sprintf("httproute host <%v%v> conflicts with an existing httproute host <%v>", [inp_host, inp_path, inv_host])
}

# =============================================================================
# VIOLATION RULES - IngressRoute as input
# =============================================================================

# IngressRoute vs Ingress
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, route.match, -1)
	inp_path := path_matches[_][1]
	other := data.inventory.namespace[ns]["networking.k8s.io/v1"].Ingress[name]
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing ingress", [inp_host, inp_path])
}

# IngressRoute vs Ingress (no path in input = all paths)
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	not regex.match(traefik_path_pattern, route.match)
	other := data.inventory.namespace[ns]["networking.k8s.io/v1"].Ingress[name]
	inv_host := other.spec.rules[_].host
	inv_path := other.spec.rules[_].http.paths[_].path
	host_conflict(inp_host, inv_host)
	path_overlap("", inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing ingress", [inp_host, ""])
}

# IngressRoute vs Gateway
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, route.match, -1)
	inp_path := path_matches[_][1]
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]
	inv_host := gw.spec.listeners[_].hostname
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with a gateway", [inp_host, inp_path])
}

# IngressRoute vs Gateway (no path in input = all paths)
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	not regex.match(traefik_path_pattern, route.match)
	gw := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].Gateway[name]
	inv_host := gw.spec.listeners[_].hostname
	host_conflict(inp_host, inv_host)
	path_overlap("", "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with a gateway", [inp_host, ""])
}

# IngressRoute vs HTTPRoute
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, route.match, -1)
	inp_path := path_matches[_][1]
	other := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	inv_host := other.spec.hostnames[_]
	inv_path := other.spec.rules[_].matches[_].path.value
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing httproute", [inp_host, inp_path])
}

# IngressRoute vs HTTPRoute (no path in input = all paths)
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	not regex.match(traefik_path_pattern, route.match)
	other := data.inventory.namespace[ns]["gateway.networking.k8s.io/v1"].HTTPRoute[name]
	inv_host := other.spec.hostnames[_]
	inv_path := other.spec.rules[_].matches[_].path.value
	host_conflict(inp_host, inv_host)
	path_overlap("", inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing httproute", [inp_host, ""])
}

# IngressRoute vs IngressRoute
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, route.match, -1)
	inp_path := path_matches[_][1]
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	inv_path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, inv_match, -1)
	inv_path := inv_path_matches[_][1]
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# IngressRoute vs IngressRoute (no path in input = all paths)
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	not regex.match(traefik_path_pattern, route.match)
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	inv_path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, inv_match, -1)
	inv_path := inv_path_matches[_][1]
	host_conflict(inp_host, inv_host)
	path_overlap("", inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing ingressroute", [inp_host, ""])
}

# IngressRoute vs IngressRoute (no path in inventory = all paths)
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, route.match, -1)
	inp_path := path_matches[_][1]
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	not regex.match(traefik_path_pattern, inv_match)
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# IngressRoute vs IngressRoute (no path in either = all paths)
violation contains {"msg": msg} if {
	input_is_traefik_ingressroute
	route := input.review.object.spec.routes[_]
	matches := regex.find_all_string_submatch_n(traefik_host_pattern, route.match, -1)
	inp_host := matches[_][1]
	not regex.match(traefik_path_pattern, route.match)
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	not regex.match(traefik_path_pattern, inv_match)
	host_conflict(inp_host, inv_host)
	path_overlap("", "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingressroute host <%v%v> conflicts with an existing ingressroute", [inp_host, ""])
}

# =============================================================================
# VIOLATION RULES - Other kinds vs IngressRoute (reverse direction)
# =============================================================================

# Ingress vs IngressRoute
violation contains {"msg": msg} if {
	input_is_ingress
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	regex.match(traefik_path_pattern, inv_match)
	inv_path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, inv_match, -1)
	inv_path := inv_path_matches[_][1]
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# Ingress vs IngressRoute (no path in Traefik = all paths)
violation contains {"msg": msg} if {
	input_is_ingress
	inp_host := input.review.object.spec.rules[_].host
	inp_path := input.review.object.spec.rules[_].http.paths[_].path
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	not regex.match(traefik_path_pattern, inv_match)
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("ingress host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# Gateway vs IngressRoute
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	inp_path := ""
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	regex.match(traefik_path_pattern, inv_match)
	inv_path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, inv_match, -1)
	inv_path := inv_path_matches[_][1]
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("gateway host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# Gateway vs IngressRoute (no path in Traefik = all paths)
violation contains {"msg": msg} if {
	input_is_gateway
	inp_host := input.review.object.spec.listeners[_].hostname
	inp_path := ""
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	not regex.match(traefik_path_pattern, inv_match)
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("gateway host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# HTTPRoute vs IngressRoute
violation contains {"msg": msg} if {
	input_is_httproute
	inp_host := input.review.object.spec.hostnames[_]
	inp_path := input.review.object.spec.rules[_].matches[_].path.value
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	regex.match(traefik_path_pattern, inv_match)
	inv_path_matches := regex.find_all_string_submatch_n(traefik_path_pattern, inv_match, -1)
	inv_path := inv_path_matches[_][1]
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, inv_path)
	not skip_same_namespace(ns, input.review)
	msg := sprintf("httproute host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}

# HTTPRoute vs IngressRoute (no path in Traefik = all paths)
violation contains {"msg": msg} if {
	input_is_httproute
	inp_host := input.review.object.spec.hostnames[_]
	inp_path := input.review.object.spec.rules[_].matches[_].path.value
	other := data.inventory.namespace[ns]["traefik.io/v1alpha1"].IngressRoute[name]
	inv_match := other.spec.routes[_].match
	inv_matches := regex.find_all_string_submatch_n(traefik_host_pattern, inv_match, -1)
	inv_host := inv_matches[_][1]
	not regex.match(traefik_path_pattern, inv_match)
	host_conflict(inp_host, inv_host)
	path_overlap(inp_path, "")
	not skip_same_namespace(ns, input.review)
	msg := sprintf("httproute host <%v%v> conflicts with an existing ingressroute", [inp_host, inp_path])
}
