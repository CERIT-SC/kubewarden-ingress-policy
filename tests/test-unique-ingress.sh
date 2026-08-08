#!/usr/bin/env bash
set -u

NS_A=ns-a
NS_B=ns-b
TEMPLATE=ingress-template.yaml
PASS=0; FAIL=0

apply_ing() {                    # $1=ns $2=host $3=path
  TEST_HOST="$2" TEST_PATH="$3" envsubst < "$TEMPLATE" \
    | kubectl -n "$1" apply -f - >/dev/null 2>&1
}

clean() {
  kubectl -n "$NS_A" delete ingress test --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS_B" delete ingress test --ignore-not-found >/dev/null 2>&1
}

# $1=test_name $2=host_a $3=path_a $4=host_b $5=path_b $6=expectation (allow|deny for ns-b)
run_test() {
  local name=$1 host_a=$2 path_a=$3 host_b=$4 path_b=$5 expect=$6
  clean
  if ! apply_ing "$NS_A" "$host_a" "$path_a"; then
    printf "\033[31mFAIL\033[0m $name: fail also for ns A (expected OK)\n"
    FAIL=$((FAIL+1)); return
  fi
  sleep 1
  apply_ing "$NS_B" "$host_b" "$path_b"
  local rc=$?

  if { [ "$expect" = deny ] && [ $rc -ne 0 ]; } || \
     { [ "$expect" = allow ] && [ $rc -eq 0 ]; }; then
    printf "\033[32mPASS\033[0m $name\n"
    PASS=$((PASS+1))
  else
    printf "\033[31mFAIL\033[0m $name (ns B: expected $expect)\n"
    FAIL=$((FAIL+1))
  fi
  clean
}

kubectl get ns "$NS_A" >/dev/null 2>&1 || kubectl create ns "$NS_A" >/dev/null
kubectl get ns "$NS_B" >/dev/null 2>&1 || kubectl create ns "$NS_B" >/dev/null

# --- reject cases ---
run_test "same-host"            app.example.com       /         app.example.com    /     deny
run_test "wildcard-same"         '*.example.com'      /          '*.example.com'   /     deny
run_test "wildcard-overlap"      '*.example.com'      /         app.example.com    /     deny
run_test "wildcard-overlap-2"   app.example.com       /          '*.example.com'   /     deny
run_test "wildcard-sub"      '*.foo.example.com'      /     app.foo.example.com    /     deny
run_test "wildcard-sub-2"   app.foo.example.com       /      '*.foo.example.com'   /     deny

# --- allow cases ---
run_test "wildcard-host"         '*.example.com'      /            'example.com'   /     allow
run_test "wildcard-host-2"         'example.com'      /          '*.example.com'   /     allow
run_test "wildcard-diff"     '*.app.example.com'      /    '*.other.example.com'   /     allow
run_test "same-host-diff-path"  app.example.com       /a        app.example.com    /b    allow
run_test "same-host-sub"        app.example.com       /     sub.app.example.com    /     allow
run_test "diff-host"            app.example.com       /       other.example.com    /     allow
run_test "diff-host-same-path"  app.example.com       /api    other.example.com    /api  allow

echo
echo "=== PASS: $PASS  FAIL: $FAIL ==="
[ "$FAIL" -eq 0 ]
