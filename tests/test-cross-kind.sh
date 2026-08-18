#!/usr/bin/env bash
set -u

NS_A=ns-a
NS_B=ns-b
INGRESS_TEMPLATE=ingress-template.yaml
GATEWAY_TEMPLATE=gateway-template.yaml
HTTROUTE_TEMPLATE=httproute-template.yaml
PASS=0; FAIL=0

apply_resource() {               # $1=kind $2=ns $3=host $4=path (path="-" for Gateway)
  local kind=$1 ns=$2 host=$3 path=$4
  case "$kind" in
    ing) TEST_HOST="$host" TEST_PATH="$path" envsubst <  "$INGRESS_TEMPLATE" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
    gw)  TEST_HOST="$host"                   envsubst <  "$GATEWAY_TEMPLATE" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
    hr)  TEST_HOST="$host" TEST_PATH="$path" envsubst < "$HTTROUTE_TEMPLATE" | kubectl -n "$ns" apply -f - >/dev/null 2>&1 ;;
  esac
}

delete_resource() {              # $1=kind $2=ns
  local kind=$1 ns=$2
  case "$kind" in
    ing) kubectl -n "$ns" delete   ingress test --ignore-not-found >/dev/null 2>&1 ;;
    gw)  kubectl -n "$ns" delete   gateway test --ignore-not-found >/dev/null 2>&1 ;;
    hr)  kubectl -n "$ns" delete httproute test --ignore-not-found >/dev/null 2>&1 ;;
  esac
}

clean_all() {
  delete_resource ing "$NS_A"
  delete_resource ing "$NS_B"
  delete_resource gw "$NS_A"
  delete_resource gw "$NS_B"
  delete_resource hr "$NS_A"
  delete_resource hr "$NS_B"
}

# Generic test runner
# Usage: run_test name kind_a host_a path_a kind_b host_b path_b expect
run_test() {
  local name=$1 kind_a=$2 host_a=$3 path_a=$4 kind_b=$5 host_b=$6 path_b=$7 expect=$8
  clean_all

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
  clean_all
}

# Define test scenarios ONCE (matching test-unique-ingress.sh structure)
# Format: name host_a path_a host_b path_b expect
declare -a SCENARIOS=(
  # Reject cases
  "same-host                app.example.com   /          app.example.com   /      deny"
  "wildcard-same              *.example.com   /            *.example.com   /      deny"
  "wildcard-overlap           *.example.com   /          app.example.com   /      deny"
  "wildcard-overlap-r       app.example.com   /            *.example.com   /      deny"
  "wildcard-overlap-2   sub.app.example.com   /            *.example.com   /      deny"
  "wildcard-sub           *.foo.example.com   /      app.foo.example.com   /      deny"
  "wildcard-sub-r       app.foo.example.com   /        *.foo.example.com   /      deny"
  # Allow cases
  "wildcard-host              *.example.com   /              example.com   /      allow"
  "wildcard-host-r              example.com   /            *.example.com   /      allow"
  "wildcard-diff          *.app.example.com   /      *.other.example.com   /      allow"
  "same-host-diff-path      app.example.com   /a         app.example.com   /b     allow"
  "same-host-sub            app.example.com   /      sub.app.example.com   /      allow"
  "diff-host                app.example.com   /        other.example.com   /      allow"
  "diff-host-same-path      app.example.com   /api     other.example.com   /api   allow"
)

# Resource kinds to test: "kind_name:display_name:has_path"
declare -a KINDS=( "ing:Ingress:yes" "gw:Gateway:no" "hr:HTTPRoute:yes" )

kubectl get ns "$NS_A" >/dev/null 2>&1 || kubectl create ns "$NS_A" >/dev/null
kubectl get ns "$NS_B" >/dev/null 2>&1 || kubectl create ns "$NS_B" >/dev/null

# Run tests for all kind combinations
for combo_a in "${KINDS[@]}"; do
  IFS=':' read -r kind_a name_a has_path_a <<< "$combo_a"

  for combo_b in "${KINDS[@]}"; do
    IFS=':' read -r kind_b name_b has_path_b <<< "$combo_b"

    echo "=== ${name_a} vs ${name_b} tests ==="

    for scenario in "${SCENARIOS[@]}"; do
      read -r name host_a path_a host_b path_b expect <<< "$scenario"

      # Skip if either resource doesn't support paths but scenario has paths
      if [[ "$has_path_a" == "no" && "$path_a" != "/" ]]; then
        continue
      fi
      if [[ "$has_path_b" == "no" && "$path_b" != "/" ]]; then
        continue
      fi

      # Use "-" for Gateway path, otherwise use the scenario path
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

echo "=== PASS: $PASS  FAIL: $FAIL ==="
[ "$FAIL" -eq 0 ]
