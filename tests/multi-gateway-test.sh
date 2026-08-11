#!/usr/bin/env bash
set -u

NS_A=ns-a
NS_B=ns-b
INGRESS_TEMPLATE=ingress-template.yaml
GATEWAY_TEMPLATE=gateway-template.yaml
HTTROUTE_TEMPLATE=httproute-template.yaml
PASS=0; FAIL=0

apply_ing() {                    # $1=ns $2=host $3=path
  TEST_HOST="$2" TEST_PATH="$3" envsubst < "$INGRESS_TEMPLATE" \
    | kubectl -n "$1" apply -f - >/dev/null 2>&1
}

apply_gateway() {                # $1=ns $2=host
  TEST_HOST="$2" envsubst < "$GATEWAY_TEMPLATE" \
    | kubectl -n "$1" apply -f - >/dev/null 2>&1
}

apply_httproute() {              # $1=ns $2=host $3=path
  TEST_HOST="$2" TEST_PATH="$3" envsubst < "$HTTROUTE_TEMPLATE" \
    | kubectl -n "$1" apply -f - >/dev/null 2>&1
}

clean() {
  kubectl -n "$NS_A" delete ingress test --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS_B" delete ingress test --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS_A" delete gateway test --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS_B" delete gateway test --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS_A" delete httproute test --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS_B" delete httproute test --ignore-not-found >/dev/null 2>&1
}

# --- Ingress vs Ingress tests ---
run_ingress_test() {
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

# --- Gateway tests ---
run_gateway_test() {
  local name=$1 type=$2 host_a=$3 host_b=$4 expect=$5
  clean
  if [ "$type" = "ing" ]; then
    if ! apply_ing "$NS_A" "$host_a" "/"; then
      printf "\033[31mFAIL\033[0m $name: fail also for ns A ingress (expected OK)\n"
      FAIL=$((FAIL+1)); return
    fi
  else
    if ! apply_gateway "$NS_A" "$host_a"; then
      printf "\033[31mFAIL\033[0m $name: fail also for ns A gateway (expected OK)\n"
      FAIL=$((FAIL+1)); return
    fi
  fi
  sleep 1
  apply_gateway "$NS_B" "$host_b"
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

# --- HTTPRoute tests ---
run_httproute_test() {
  local name=$1 type=$2 host_a=$3 path_a=$4 host_b=$5 path_b=$6 expect=$7
  clean
  if [ "$type" = "ing" ]; then
    if ! apply_ing "$NS_A" "$host_a" "$path_a"; then
      printf "\033[31mFAIL\033[0m $name: fail also for ns A ingress (expected OK)\n"
      FAIL=$((FAIL+1)); return
    fi
  elif [ "$type" = "gw" ]; then
    if ! apply_gateway "$NS_A" "$host_a"; then
      printf "\033[31mFAIL\033[0m $name: fail also for ns A gateway (expected OK)\n"
      FAIL=$((FAIL+1)); return
    fi
  else
    if ! apply_httproute "$NS_A" "$host_a" "$path_a"; then
      printf "\033[31mFAIL\033[0m $name: fail also for ns A httproute (expected OK)\n"
      FAIL=$((FAIL+1)); return
    fi
  fi
  sleep 1
  apply_httproute "$NS_B" "$host_b" "$path_b"
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

echo "=== Ingress vs Ingress tests ==="
# --- reject cases ---
run_ingress_test "ing-ing-same-host"            app.example.com       /         app.example.com    /     deny
run_ingress_test "ing-ing-wildcard-same"        '*.example.com'       /          '*.example.com'   /     deny
run_ingress_test "ing-ing-wildcard-overlap"     '*.example.com'       /         app.example.com    /     deny
run_ingress_test "ing-ing-wildcard-overlap-2"   app.example.com       /          '*.example.com'   /     deny

# --- allow cases ---
run_ingress_test "ing-ing-wildcard-host"        '*.example.com'       /            'example.com'   /     allow
run_ingress_test "ing-ing-wildcard-host-2"      'example.com'         /          '*.example.com'   /     allow
run_ingress_test "ing-ing-wildcard-diff"        '*.app.example.com'   /    '*.other.example.com'   /     allow
run_ingress_test "ing-ing-same-host-diff-path"  app.example.com       /a        app.example.com    /b    allow
run_ingress_test "ing-ing-same-host-sub"        app.example.com       /     sub.app.example.com    /     allow
run_ingress_test "ing-ing-diff-host"            app.example.com       /       other.example.com    /     allow

echo
echo "=== Gateway vs Gateway tests ==="
# --- reject cases ---
run_gateway_test "gw-gw-same-host" gw app.example.com app.example.com deny
run_gateway_test "gw-gw-wildcard-same" gw '*.example.com' '*.example.com' deny
run_gateway_test "gw-gw-wildcard-overlap" gw '*.example.com' app.example.com deny
run_gateway_test "gw-gw-wildcard-overlap-2" gw app.example.com '*.example.com' deny

# --- allow cases ---
run_gateway_test "gw-gw-wildcard-host" gw '*.example.com' example.com allow
run_gateway_test "gw-gw-wildcard-host-2" gw example.com '*.example.com' allow
run_gateway_test "gw-gw-wildcard-diff" gw '*.app.example.com' '*.other.example.com' allow
run_gateway_test "gw-gw-diff-host" gw app.example.com other.example.com allow

echo
echo "=== Gateway vs Ingress tests ==="
# --- reject cases ---
run_gateway_test "gw-ing-conflict" ing app.example.com app.example.com deny
run_gateway_test "gw-ing-wildcard-overlap" ing '*.example.com' app.example.com deny
run_gateway_test "ing-gw-wildcard-overlap" gw app.example.com '*.example.com' deny

# --- allow cases ---
run_gateway_test "gw-ing-diff-host" ing app.example.com other.example.com allow
run_gateway_test "gw-ing-wildcard-host" gw '*.example.com' example.com allow

echo
echo "=== HTTPRoute vs HTTPRoute tests ==="
# --- reject cases ---
run_httproute_test "hr-hr-same-host-same-path" hr app.example.com / app.example.com / deny
run_httproute_test "hr-hr-wildcard-same" hr '*.example.com' / '*.example.com' / deny
run_httproute_test "hr-hr-wildcard-overlap" hr '*.example.com' / app.example.com / deny

# --- allow cases ---
run_httproute_test "hr-hr-same-host-diff-path" hr app.example.com / app.example.com /api allow
run_httproute_test "hr-hr-diff-host" hr app.example.com / other.example.com / allow
run_httproute_test "hr-hr-wildcard-host" hr '*.example.com' / example.com / allow

echo
echo "=== HTTPRoute vs Ingress tests ==="
# --- reject cases ---
run_httproute_test "hr-ing-conflict" ing app.example.com / app.example.com / deny
run_httproute_test "hr-ing-wildcard-overlap" ing '*.example.com' / app.example.com / deny

# --- allow cases ---
run_httproute_test "hr-ing-diff-host" ing app.example.com / other.example.com / allow
run_httproute_test "hr-ing-same-host-diff-path" ing app.example.com / app.example.com /api allow

echo
echo "=== HTTPRoute vs Gateway tests ==="
# --- reject cases ---
run_httproute_test "hr-gw-conflict" gw app.example.com app.example.com / deny
run_httproute_test "hr-gw-wildcard-overlap" gw '*.example.com' app.example.com / deny

# --- allow cases ---
run_httproute_test "hr-gw-diff-host" gw app.example.com other.example.com / allow
run_httproute_test "hr-gw-wildcard-host" gw '*.example.com' example.com / allow

echo
echo "=== PASS: $PASS  FAIL: $FAIL ==="
[ "$FAIL" -eq 0 ]
