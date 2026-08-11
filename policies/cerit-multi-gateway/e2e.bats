#!/usr/bin/env bats

# ============================================
# INGRESS tests
# ============================================

@test "accept Ingress because host is unique" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/ingress_unique.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_empty.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject Ingress because host conflicts with existing Ingress" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/ingress_duplicate.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_ingress_dup.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "reject Ingress because host conflicts with Gateway listener" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/ingress_vs_gateway.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_gateway.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "reject Ingress because host conflicts with HTTPRoute" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/ingress_vs_httproute.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_httproute.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

# ============================================
# GATEWAY tests
# ============================================

@test "accept Gateway because listener hostname is unique" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/gateway_unique.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_empty.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject Gateway because listener hostname conflicts with Ingress" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/gateway_vs_ingress.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_ingress.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "reject Gateway because listener hostname conflicts with existing Gateway" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/gateway_duplicate.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_gateway_dup.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "reject Gateway because listener hostname conflicts with HTTPRoute" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/gateway_vs_httproute.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_httproute.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

# ============================================
# HTTPROUTE tests
# ============================================

@test "accept HTTPRoute because host is unique" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/httproute_unique.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_empty.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "reject HTTPRoute because host conflicts with Ingress" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/httproute_vs_ingress.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_ingress.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "reject HTTPRoute because host conflicts with Gateway" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/httproute_vs_gateway.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_gateway.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "reject HTTPRoute because host conflicts with existing HTTPRoute" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/httproute_duplicate.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_httproute_dup.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "accept HTTPRoute because same host but different path" {
  run kwctl run annotated-policy.wasm \
              -r ./test_data/httproute_diff_path.json \
              --allow-context-aware \
              --replay-host-capabilities-interactions ./test_data/k8s_ctx_httproute.yml
  echo "output = ${output}"
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
