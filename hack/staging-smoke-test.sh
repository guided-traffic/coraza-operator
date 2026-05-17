#!/usr/bin/env bash
# staging-smoke-test.sh: end-to-end smoke test for the coraza-operator staging cluster.
# Installs the Helm chart, applies sample resources, and verifies that the engine WAF
# correctly proxies benign requests and blocks /attack paths.
# Run from the repository root: bash hack/staging-smoke-test.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="${REPO_ROOT}/local_kube_config"
KC="kubectl --kubeconfig=${KUBECONFIG}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

step=0
fail() {
  echo -e "${RED}FAILED at step ${step}: $1${NC}" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Step 1: namespaces
# ---------------------------------------------------------------------------
step=1
echo "==> Step ${step}: create namespaces"
${KC} create namespace coraza-system --dry-run=client -o yaml | ${KC} apply -f -
${KC} create namespace coraza-demo   --dry-run=client -o yaml | ${KC} apply -f -

# ---------------------------------------------------------------------------
# Step 2: helm upgrade --install
# ---------------------------------------------------------------------------
step=2
echo "==> Step ${step}: helm upgrade --install"
helm upgrade --install coraza-operator "${REPO_ROOT}/charts/coraza-operator" \
  -n coraza-system \
  --wait \
  --timeout 3m \
  --kubeconfig "${KUBECONFIG}"

# ---------------------------------------------------------------------------
# Step 3: wait for operator Deployment Available
# ---------------------------------------------------------------------------
step=3
echo "==> Step ${step}: wait for operator Deployment Available"
${KC} -n coraza-system rollout status deployment/coraza-operator --timeout=3m \
  || fail "operator deployment did not become available"

# ---------------------------------------------------------------------------
# Step 4: apply sample workloads (ordered)
# ---------------------------------------------------------------------------
step=4
echo "==> Step ${step}: apply sample manifests"
${KC} apply -f "${REPO_ROOT}/config/samples/example_upstream.yaml"
${KC} apply -f "${REPO_ROOT}/config/samples/waf_v1_secrules_baseline.yaml"
${KC} apply -f "${REPO_ROOT}/config/samples/waf_v1_secrules_block_attack.yaml"
${KC} apply -f "${REPO_ROOT}/config/samples/waf_v1_ruleset_demo.yaml"
${KC} apply -f "${REPO_ROOT}/config/samples/waf_v1_engine_demo.yaml"

# ---------------------------------------------------------------------------
# Step 4b: wait for example-upstream deployment
# ---------------------------------------------------------------------------
step=4
echo "==> Step ${step}b: wait for example-upstream deployment ready"
${KC} -n coraza-demo rollout status deployment/example-upstream --timeout=3m \
  || fail "example-upstream deployment did not become available"

# ---------------------------------------------------------------------------
# Step 5: wait for RuleSet compiledHash
# ---------------------------------------------------------------------------
step=5
echo "==> Step ${step}: wait for RuleSet/demo-ruleset compiledHash"
deadline=$(( $(date +%s) + 180 ))
while true; do
  hash=$(${KC} -n coraza-demo get ruleset demo-ruleset \
    -o jsonpath='{.status.compiledHash}' 2>/dev/null || true)
  if [[ -n "${hash}" ]]; then
    echo "    compiledHash=${hash}"
    break
  fi
  [[ $(date +%s) -lt ${deadline} ]] || fail "RuleSet/demo-ruleset never got compiledHash"
  sleep 5
done

# ---------------------------------------------------------------------------
# Step 6: wait for Engine/demo-engine Deployment readyReplicas >= 1
# ---------------------------------------------------------------------------
step=6
echo "==> Step ${step}: wait for Engine/demo-engine deployment ready"
deadline=$(( $(date +%s) + 180 ))
while true; do
  ready=$(${KC} -n coraza-demo get deployment demo-engine \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
  if [[ "${ready}" -ge 1 ]]; then
    echo "    readyReplicas=${ready}"
    break
  fi
  [[ $(date +%s) -lt ${deadline} ]] || fail "Engine/demo-engine deployment never became ready"
  sleep 5
done

# ---------------------------------------------------------------------------
# Step 6b: wait for Ready=True conditions
# ---------------------------------------------------------------------------
step=6
echo "==> Step ${step}b: wait for Ready=True conditions on RuleSet and Engine"
deadline=$(( $(date +%s) + 60 ))
while true; do
  rs_ready=$(${KC} -n coraza-demo get ruleset demo-ruleset \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  eng_ready=$(${KC} -n coraza-demo get engine demo-engine \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
  if [[ "${rs_ready}" == "True" && "${eng_ready}" == "True" ]]; then
    echo "    RuleSet Ready=True, Engine Ready=True"
    break
  fi
  [[ $(date +%s) -lt ${deadline} ]] || fail "Ready conditions not True (RuleSet=${rs_ready}, Engine=${eng_ready})"
  sleep 5
done

# ---------------------------------------------------------------------------
# Step 7: find the engine service and start port-forward
# ---------------------------------------------------------------------------
step=7
echo "==> Step ${step}: port-forward to engine service"
LOCAL_PORT=18080
# Kill any stale port-forward on that port.
lsof -ti tcp:${LOCAL_PORT} 2>/dev/null | xargs -r kill -9 || true

${KC} -n coraza-demo port-forward svc/demo-engine-svc ${LOCAL_PORT}:8080 &
PF_PID=$!
trap 'kill ${PF_PID} 2>/dev/null || true' EXIT

# ---------------------------------------------------------------------------
# Step 8: sleep for tunnel to stabilise
# ---------------------------------------------------------------------------
step=8
echo "==> Step ${step}: waiting for tunnel"
sleep 3

# ---------------------------------------------------------------------------
# Step 9: curl tests
# ---------------------------------------------------------------------------
step=9
echo "==> Step ${step}: curl tests"
BASE="http://localhost:${LOCAL_PORT}"

# 9a: /healthz → 200
echo "    GET /healthz"
code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/healthz")
[[ "${code}" == "200" ]] || fail "/healthz returned HTTP ${code}, expected 200"
echo "    /healthz -> 200 OK"

# 9b: /readyz → 200
echo "    GET /readyz"
code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/readyz")
[[ "${code}" == "200" ]] || fail "/readyz returned HTTP ${code}, expected 200"
echo "    /readyz -> 200 OK"

# 9c: benign path → 200 (proxied to example-upstream)
echo "    GET / (benign)"
code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/")
[[ "${code}" == "200" ]] || fail "GET / returned HTTP ${code}, expected 200"
echo "    GET / -> 200 OK"

# 9d: /attack → 403 (blocked by SecRule id:1001)
echo "    GET /attack (should be blocked)"
code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/attack")
[[ "${code}" == "403" ]] || fail "GET /attack returned HTTP ${code}, expected 403"
echo "    GET /attack -> 403 BLOCKED OK"

# ---------------------------------------------------------------------------
# Step 10: kill port-forward (handled by trap)
# ---------------------------------------------------------------------------
step=10
echo "==> Step ${step}: cleaning up port-forward"
kill "${PF_PID}" 2>/dev/null || true
trap - EXIT

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}SMOKE TEST PASSED${NC}"
