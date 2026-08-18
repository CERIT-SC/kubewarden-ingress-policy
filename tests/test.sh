#!/usr/bin/env bash
# Unified test script for all policy test suites
# Usage: ./test-all.sh [unique-ingress|cross-kind|cross-traefik]

set -u

NS_A=ns-a
NS_B=ns-b
PASS=0; FAIL=0

# Templates
INGRESS_TEMPLATE=ingress-template.yaml
GATEWAY_TEMPLATE=gateway-template.yaml
HTTROUTE_TEMPLATE=httproute-template.yaml

# Test scenarios (shared across all suites)
declare -a SCENARIOS=(
  # Reject cases
  "same-host                app.example.com   /          app.example.com   /      deny"
  "wildcard-same              *.example.com   /            *.example.com   /      deny"
  "wildcard-overlap           *.example.com   /          app.example.com   /      deny"
  "wildcard-overlap-r       app.example.com   /            *.example.com   /      deny"
  "wildcard-overlap-2   sub.app.example.com   /            *.example.com   /      deny"
  "wildcard-overlap-2-r       *.example.com   /      sub.app.example.com   /      deny"
  "wildcard-sub           *.foo.example.com   /      app.foo.example.com   /      deny"
  "wildcard-sub-r       app.foo.example.com   /        *.foo.example.com   /      deny"
  # Allow cases
  "wildcard-host              *.example.com   /              example.com   /      allow"
  "wildcard-host-r              example.com   /            *.example.com   /      allow"
  "wildcard-diff          *.app.example.com   /      *.other.example.com   /      allow"
  "same-host-diff-path      app.example.com   /a         app.example.com   /b     allow"
  "same-host-sub            app.example.com   /      sub.app.example.com   /      allow"
  "same-host-sub-r      sub.app.example.com   /          app.example.com   /      allow"
  "diff-host                app.example.com   /        other.example.com   /      allow"
  "diff-host-same-path      app.example.com   /api     other.example.com   /api   allow"
)

apply_resource() {               # $1=kind $2=ns $3=host $4=path
  local kind=$1 ns=$2 host=$3 path=$4
  case "$kind" in
    ing) TEST_HOST="$host" TEST_PATH="$path" envsubst <  "$INGRESS_TEMPLATE" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
    gw)  TEST_HOST="$host"                   envsubst <  "$GATEWAY_TEMPLATE" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
    hr)  TEST_HOST="$host" TEST_PATH="$path" envsubst < "$HTTROUTE_TEMPLATE" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
    ir)  local match="Host(\`$host\`)"; [ "$path" != "-" ] && [ "$path" != "/" ] && match="${match} && PathPrefix(\`$path\`)"; printf '%s\n' "apiVersion: traefik.io/v1alpha1" "kind: IngressRoute" "metadata:" "  name: test" "spec:" "  routes:" "  - match: $match" "    kind: Rule" "    services:" "    - name: test" "      port: 80" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
  esac
}

delete_resource() {              # $1=kind $2=ns
  local kind=$1 ns=$2
  case "$kind" in
    ing) kubectl -n "$ns" delete      ingress test --ignore-not-found >/dev/null 2>&1 ;;
    gw)  kubectl -n "$ns" delete      gateway test --ignore-not-found >/dev/null 2>&1 ;;
    hr)  kubectl -n "$ns" delete    httproute test --ignore-not-found >/dev/null 2>&1 ;;
    ir)  kubectl -n "$ns" delete ingressroute test --ignore-not-found >/dev/null 2>&1 ;;
  esac
}

clean_all() {
  local kinds=${1:-"ing"}
  for kind in $kinds; do
    delete_resource "$kind" "$NS_A"
    delete_resource "$kind" "$NS_B"
  done
}

run_test() {                     # $1=name $2=kind_a $3=host_a $4=path_a $5=kind_b $6=host_b $7=path_b $8=expect
  local name=$1 kind_a=$2 host_a=$3 path_a=$4 kind_b=$5 host_b=$6 path_b=$7 expect=$8
  local kinds="ing"
  [[ "$kind_a" == "gw" || "$kind_b" == "gw" ]] && kinds="$kinds gw"
  [[ "$kind_a" == "hr" || "$kind_b" == "hr" ]] && kinds="$kinds hr"
  [[ "$kind_a" == "ir" || "$kind_b" == "ir" ]] && kinds="$kinds ir"
  clean_all "$kinds"

  if ! apply_resource "$kind_a" "$NS_A" "$host_a" "$path_a"; then
    printf "\033[31mFAIL\033[0m %s: fail also for ns A (expected OK)\n" "$name"
    FAIL=$((FAIL+1)); return
  fi
  sleep 0.3

  apply_resource "$kind_b" "$NS_B" "$host_b" "$path_b"
  local rc=$?

  if { [ "$expect" =  deny ] && [ $rc -ne 0 ]; } || \
     { [ "$expect" = allow ] && [ $rc -eq 0 ]; }; then
    printf "\033[32mPASS\033[0m %s\n" "$name"
    PASS=$((PASS+1))
  else
    printf "\033[31mFAIL\033[0m %s (ns B: expected %s)\n" "$name" "$expect"
    FAIL=$((FAIL+1))
  fi
  clean_all "$kinds"
}

# Setup namespaces
kubectl get ns "$NS_A" >/dev/null 2>&1 || kubectl create ns "$NS_A" >/dev/null
kubectl get ns "$NS_B" >/dev/null 2>&1 || kubectl create ns "$NS_B" >/dev/null

SUITE="${1:-help}"

case "$SUITE" in
  unique-ingress)
    echo "=== Testing unique-ingress policy ==="
    echo
    for scenario in "${SCENARIOS[@]}"; do
      read -r name host_a path_a host_b path_b expect <<< "$scenario"
      run_test "${name}" "ing" "$host_a" "$path_a" "ing" "$host_b" "$path_b" "$expect"
    done
    echo
    ;;

  cross-kind)
    echo "=== Testing cross-kind policy ==="
    echo
    declare -a KINDS=( "ing:Ingress:yes" "gw:Gateway:no" "hr:HTTPRoute:yes" )

    for combo_a in "${KINDS[@]}"; do
      IFS=':' read -r kind_a name_a has_path_a <<< "$combo_a"

      for combo_b in "${KINDS[@]}"; do
        IFS=':' read -r kind_b name_b has_path_b <<< "$combo_b"

        echo "--- ${name_a} vs ${name_b} ---"

        for scenario in "${SCENARIOS[@]}"; do
          read -r name host_a path_a host_b path_b expect <<< "$scenario"

          [[ "$has_path_a" == "no" && "$path_a" != "/" ]] && continue
          [[ "$has_path_b" == "no" && "$path_b" != "/" ]] && continue

          actual_path_a="$path_a"
          actual_path_b="$path_b"
          [[ "$has_path_a" == "no" ]] && actual_path_a="-"
          [[ "$has_path_b" == "no" ]] && actual_path_b="-"

          run_test "${kind_a}-${kind_b}-${name}" "$kind_a" "$host_a" "$actual_path_a" \
                   "$kind_b" "$host_b" "$actual_path_b" "$expect"
        done
        echo
      done
    done
    ;;

  cross-traefik)
    echo "=== Testing cross-traefik policy ==="
    echo
    declare -a KINDS=( "ing:Ingress:yes" "gw:Gateway:no" "hr:HTTPRoute:yes" "ir:IngressRoute:no" )

    for combo_a in "${KINDS[@]}"; do
      IFS=':' read -r kind_a name_a has_path_a <<< "$combo_a"

      for combo_b in "${KINDS[@]}"; do
        IFS=':' read -r kind_b name_b has_path_b <<< "$combo_b"

        echo "--- ${name_a} vs ${name_b} ---"

        for scenario in "${SCENARIOS[@]}"; do
          read -r name host_a path_a host_b path_b expect <<< "$scenario"

          [[ "$has_path_a" == "no" && "$path_a" != "/" ]] && continue
          [[ "$has_path_b" == "no" && "$path_b" != "/" ]] && continue

          actual_path_a="$path_a"
          actual_path_b="$path_b"
          [[ "$has_path_a" == "no" ]] && actual_path_a="-"
          [[ "$has_path_b" == "no" ]] && actual_path_b="-"

          run_test "${kind_a}-${kind_b}-${name}" "$kind_a" "$host_a" "$actual_path_a" \
                   "$kind_b" "$host_b" "$actual_path_b" "$expect"
        done
        echo
      done
    done
    ;;

  *)
    echo "Usage: $0 [unique-ingress|cross-kind|cross-traefik]"
    echo ""
    echo "Test suites:"
    echo "  unique-ingress   - Test Ingress-only conflicts (1 kind)"
    echo "  cross-kind       - Test Ingress, Gateway, HTTPRoute conflicts (3 kinds)"
    echo "  cross-traefik    - Test all kinds including Traefik IngressRoute (4 kinds)"
    exit 1
    ;;
esac

echo
echo "=========================================="
echo "SUMMARY: PASS: $PASS  FAIL: $FAIL"
echo "=========================================="
[ "$FAIL" -eq 0 ]
