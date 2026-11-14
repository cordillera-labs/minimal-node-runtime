#!/usr/bin/env bash
#
# Tests for dependency-advisory-audit.sh, the gate that runs `pnpm audit` in
# every tracked lockfile root and tells a finding (exit 1) from a fault (exit 69).
#
# The tests run the real script against throwaway git repositories and a stub
# `pnpm` on PATH. The stub prints the audit report a fixture root holds and
# exits with the status that root holds, so no test reaches the network. The
# stub also logs the directory of every call, which is how a test proves the
# script audited a root rather than passing without reading one.

set -euo pipefail

AUDIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dependency-advisory-audit.sh"
[[ -f "${AUDIT}" ]] || { echo "missing ${AUDIT}" >&2; exit 1; }

passed=0
failed=0
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
pass() { printf '  ok    %s\n' "$1"; passed=$((passed + 1)); }
fail() { printf '  FAIL  %s\n' "$1"; failed=$((failed + 1)); }

# The stub. Each fixture root holds `stub-report.json` (what `pnpm audit --json`
# prints), `stub-status` (its exit status; `pnpm audit` exits 1 on a finding and
# on a registry error alike) and, optionally, `stub-sleep` (seconds to hang).
stub_bin="${work}/bin"
mkdir -p "${stub_bin}"
cat > "${stub_bin}/pnpm" <<'STUB'
#!/usr/bin/env bash
printf '%s\t%s\n' "${PWD}" "$*" >> "${STUB_CALL_LOG}"
[[ ! -f stub-sleep ]] || sleep "$(cat stub-sleep)"
cat stub-report.json
exit "$(cat stub-status)"
STUB
chmod +x "${stub_bin}/pnpm"

# fixture NAME — a fresh git repository; add roots to it with add_root.
fixture() {
	repo="${work}/$1"
	mkdir -p "${repo}"
	git -C "${repo}" init --quiet
	STUB_CALL_LOG="${work}/$1.calls"
	: > "${STUB_CALL_LOG}"
	export STUB_CALL_LOG
}
# advisory_entries CRITICAL HIGH MODERATE LOW — the `advisories` object entries,
# one per advisory, each keyed by a distinct id and carrying its severity.
advisory_entries() {
	local entries=() severity count i id=0
	for severity in critical high moderate low; do
		count="$1"; shift
		for ((i = 0; i < count; i++)); do
			id=$((id + 1))
			entries+=("$(printf '"%s":{"id":%s,"severity":"%s","module_name":"pkg-%s"}' "${id}" "${id}" "${severity}" "${id}")")
		done
	done
	local IFS=,
	printf '%s' "${entries[*]}"
}
# report CRITICAL HIGH MODERATE LOW — the JSON `pnpm audit --json` prints: one
# `advisories` entry per advisory, and the same counts in `metadata.vulnerabilities`.
report() {
	printf '{"advisories":{%s},"metadata":{"vulnerabilities":{"info":0,"low":%s,"moderate":%s,"high":%s,"critical":%s},"dependencies":10,"devDependencies":0,"optionalDependencies":0,"totalDependencies":10}}' "$(advisory_entries "$1" "$2" "$3" "$4")" "$4" "$3" "$2" "$1"
}
# ignored_report — the JSON pnpm prints when the only advisory is listed in
# `auditConfig.ignoreGhsas`: the advisory leaves `advisories`, and
# `metadata.vulnerabilities` still counts it.
ignored_report() {
	printf '{"advisories":{},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":0},"dependencies":10,"devDependencies":0,"optionalDependencies":0,"totalDependencies":10}}'
}
# add_root DIRECTORY REPORT STATUS — a tracked lockfile root whose stub answers REPORT.
add_root() {
	local directory="$1"
	mkdir -p "${repo}/${directory}"
	printf 'lockfileVersion: 9.0\n' > "${repo}/${directory}/pnpm-lock.yaml"
	printf '%s' "$2" > "${repo}/${directory}/stub-report.json"
	printf '%s' "$3" > "${repo}/${directory}/stub-status"
	git -C "${repo}" add "${directory}/pnpm-lock.yaml"
}
run_audit() {
	set +e
	output="$(PATH="${stub_bin}:${PATH}" bash "${AUDIT}" "$@" "${repo}" 2>"${work}/stderr")"
	status=$?
	set -e
	error_output="$(cat "${work}/stderr")"
}
audited_directories() { cut -f1 "${STUB_CALL_LOG}" | sort; }

echo "--- a clean root passes"
fixture clean
add_root app "$(report 0 0 0 0)" 0
run_audit
[[ "$(wc -l < "${STUB_CALL_LOG}")" -eq 1 ]] && pass "precondition: the stub audited exactly one root, so the pass below is not vacuous" || fail "precondition: the stub was called $(wc -l < "${STUB_CALL_LOG}") times"
[[ "${status}" == 0 ]] && pass "exit 0" || fail "exit ${status}: ${output} ${error_output}"
grep -qF 'app: critical=0 high=0 moderate=0 low=0' <<< "${output}" && pass "the counts are printed" || fail "output: ${output}"
grep -qF -- '--json' "${STUB_CALL_LOG}" && pass "pnpm audit runs with --json" || fail "call log: $(cat "${STUB_CALL_LOG}")"

echo "--- an advisory pnpm ignores through auditConfig.ignoreGhsas is not a finding"
fixture ignored
add_root . "$(ignored_report)" 1
run_audit
[[ "$(wc -l < "${STUB_CALL_LOG}")" -eq 1 ]] && pass "precondition: the stub audited the root, and its metadata still counts one high advisory" || fail "precondition: the stub was called $(wc -l < "${STUB_CALL_LOG}") times"
[[ "${status}" == 0 ]] && pass "exit 0: the gate counts the advisories pnpm reports, not the metadata total" || fail "exit ${status}: ${output} ${error_output}"
grep -qF '(repository root): critical=0 high=0 moderate=0 low=0' <<< "${output}" && pass "the ignored advisory is not counted" || fail "output: ${output}"

echo "--- a root with a high advisory is a finding"
fixture high
add_root app "$(report 0 2 5 1)" 1
run_audit
[[ "${status}" == 1 ]] && pass "exit 1" || fail "exit ${status}: ${output} ${error_output}"
grep -qF 'app: critical=0 high=2 moderate=5 low=1' <<< "${output}" && pass "the counts are printed" || fail "output: ${output}"
grep -qF 'FINDING' <<< "${output}" && pass "the root is named as a finding" || fail "output: ${output}"
fixture critical
add_root app "$(report 1 0 0 0)" 1
run_audit
[[ "${status}" == 1 ]] && pass "a critical advisory alone is a finding" || fail "critical: exit ${status}"

echo "--- findings identify the package and recommended version"
fixture advisory-detail
add_root app '{"advisories":{"123":{"id":123,"severity":"high","module_name":"undici","title":"Improper header parsing","url":"https://github.com/advisories/GHSA-abcd-1234-wxyz","vulnerable_versions":"<7.30.1","patched_versions":">=7.30.1","findings":[{"version":"7.29.1"}]}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":0}}}' 1
run_audit
[[ "${status}" == 1 ]] && pass "an advisory with a fix still blocks" || fail "advisory detail exit ${status}"
grep -qF 'HIGH undici (installed: 7.29.1) [GHSA-abcd-1234-wxyz] - Improper header parsing' <<< "${output}" && pass "package, installed version, title and GHSA are printed" || fail "output: ${output}"
grep -qF 'Vulnerable: <7.30.1; patched range: >=7.30.1' <<< "${output}" && pass "vulnerable and patched ranges are printed" || fail "output: ${output}"
grep -qF 'Recommended: Upgrade undici to a release satisfying >=7.30.1' <<< "${output}" && pass "recommended upgrade is actionable" || fail "output: ${output}"
grep -qF 'Advisory: https://github.com/advisories/GHSA-abcd-1234-wxyz' <<< "${output}" && pass "advisory link is printed" || fail "output: ${output}"

echo "--- missing patch is explicit and registry text cannot forge log commands"
fixture advisory-unfixed
add_root app '{"advisories":{"456":{"id":456,"severity":"critical","module_name":"unfixed-lib","title":"Bad payload\n::error::forged","vulnerable_versions":"<=2.0.0","patched_versions":null,"findings":[{"version":"2.0.0"}]}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":1}}}' 1
run_audit
[[ "${status}" == 1 ]] && pass "an unfixable advisory still blocks" || fail "unfixed exit ${status}"
grep -qF 'patched range: none published' <<< "${output}" && pass "missing patch not fabricated" || fail "output: ${output}"
grep -qF 'Recommended: No published patched release for unfixed-lib' <<< "${output}" && pass "remediation guidance states no fix" || fail "output: ${output}"
! grep -qxF '::error::forged' <<< "${output}" && pass "registry title cannot forge a workflow command line" || fail "unsafe output: ${output}"

echo "--- a root with moderate advisories fails at the default threshold, which is moderate"
fixture low
add_root app "$(report 0 0 3 4)" 1
run_audit
grep -qF 'low=4' <<< "${output}" && pass "precondition: the root holds advisories, so a pass is not an empty report" || fail "output: ${output}"
[[ "${status}" == 1 ]] && pass "the default threshold makes the moderate advisories a finding" || fail "default: exit ${status}: ${output} ${error_output}"
run_audit --threshold high
[[ "${status}" == 0 ]] && pass "--threshold high passes a root with only low and moderate advisories, although pnpm audit itself exited 1" || fail "high: exit ${status}"
fixture low-only
add_root app "$(report 0 0 0 2)" 1
run_audit --threshold moderate
[[ "${status}" == 0 ]] && pass "--threshold moderate passes a root holding only low advisories" || fail "low-only moderate: exit ${status}"
run_audit --threshold low
[[ "${status}" == 1 ]] && pass "--threshold low makes a low advisory a finding" || fail "low: exit ${status}"
run_audit --threshold critical
[[ "${status}" == 0 ]] && pass "--threshold critical passes a root holding only low advisories" || fail "critical: exit ${status}"
fixture high-critical-threshold
add_root app "$(report 0 3 0 0)" 1
run_audit --threshold critical
[[ "${status}" == 0 ]] && pass "--threshold critical passes a high advisory" || fail "high at critical: exit ${status}"

echo "--- a registry fault is exit 69, never a pass and never a finding"
fixture fault-error
add_root app '{"error":{"code":"ECONNREFUSED","message":"request to https://registry.npmjs.org failed"}}' 1
run_audit
[[ "${status}" == 69 ]] && pass "a registry error report is exit 69" || fail "error report: exit ${status}"
grep -qF 'FAULT' <<< "${output}" && pass "the root is named as a fault" || fail "output: ${output}"
fixture fault-html
add_root app '<html>502 Bad Gateway</html>' 1
run_audit
[[ "${status}" == 69 ]] && pass "a response that is not JSON is exit 69" || fail "html: exit ${status}"
fixture fault-empty
add_root app '' 0
run_audit
[[ "${status}" == 69 ]] && pass "an empty response with exit 0 is exit 69, not a pass" || fail "empty: exit ${status}"
fixture fault-shape
add_root app '{"advisories":{}}' 0
run_audit
[[ "${status}" == 69 ]] && pass "JSON without vulnerability counts is exit 69" || fail "shape: exit ${status}"
fixture fault-partial
add_root app '{"metadata":{"vulnerabilities":{"high":0}}}' 0
run_audit
[[ "${status}" == 69 ]] && pass "counts missing a severity are exit 69" || fail "partial: exit ${status}"
fixture fault-timeout
add_root app "$(report 0 0 0 0)" 0
printf '5' > "${repo}/app/stub-sleep"
set +e
output="$(DEPENDENCY_AUDIT_TIMEOUT_SECONDS=1 PATH="${stub_bin}:${PATH}" bash "${AUDIT}" "${repo}" 2>/dev/null)"
status=$?
set -e
[[ "${status}" == 69 ]] && pass "a request that outlives the timeout is exit 69" || fail "timeout: exit ${status}"
fixture fault-and-finding
add_root app "$(report 0 4 0 0)" 1
add_root cli '{"error":{"code":"ECONNREFUSED","message":"down"}}' 1
run_audit
[[ "${status}" == 69 ]] && pass "a fault outranks a finding in another root" || fail "fault and finding: exit ${status}"
grep -qF 'app: critical=0 high=4' <<< "${output}" && pass "the root that answered is still printed" || fail "output: ${output}"
# The fault branch prints the first 600 bytes of the response. A response larger
# than a pipe buffers once killed the script with SIGPIPE (exit 141) there, under
# pipefail, before it reached the next root.
fixture fault-large
add_root app "$(printf '<html>%0300000d</html>' 0)" 1
add_root cli "$(report 0 0 0 0)" 0
run_audit
[[ "$(wc -c < "${repo}/app/stub-report.json")" -gt 262144 ]] && pass "precondition: the fault response is larger than a pipe buffers" || fail "precondition: the fault response is only $(wc -c < "${repo}/app/stub-report.json") bytes"
[[ "${status}" == 69 ]] && pass "a fault response larger than a pipe buffers is exit 69" || fail "large fault: exit ${status}: ${error_output:0:300}"
[[ "$(wc -l < "${STUB_CALL_LOG}")" -eq 2 ]] && pass "the root after a large fault response is still audited" || fail "call log: $(cat "${STUB_CALL_LOG}")"
fixture no-lockfile
mkdir -p "${repo}/app" && printf '{}' > "${repo}/app/package.json" && git -C "${repo}" add app/package.json
run_audit
[[ "${status}" == 69 ]] && pass "a repository with no tracked lockfile is exit 69, not a pass over zero roots" || fail "no lockfile: exit ${status}"
[[ ! -s "${STUB_CALL_LOG}" ]] && pass "no audit ran" || fail "call log: $(cat "${STUB_CALL_LOG}")"

echo "--- every tracked lockfile root is audited, so a new root is covered with no edit"
fixture discovery
add_root . "$(report 0 0 0 0)" 0
add_root app "$(report 0 0 0 0)" 0
add_root plan-tracker "$(report 0 0 0 0)" 0
run_audit
[[ "${status}" == 0 ]] && pass "precondition: three clean roots pass" || fail "three roots: exit ${status}: ${output} ${error_output}"
[[ "$(audited_directories)" == "$(printf '%s\n' "${repo}" "${repo}/app" "${repo}/plan-tracker" | sort)" ]] \
	&& pass "the root workspace and both nested roots were audited" || fail "audited: $(audited_directories | tr '\n' ' ')"
grep -qF '(repository root): critical=0' <<< "${output}" && pass "the repository root is labelled" || fail "output: ${output}"
add_root packages/new-service "$(report 0 1 0 0)" 1
run_audit
[[ "${status}" == 1 ]] && pass "a newly committed root with a high advisory is a finding" || fail "new root: exit ${status}"
grep -qF 'packages/new-service: critical=0 high=1' <<< "${output}" && pass "the new root is named in the output" || fail "output: ${output}"
audited_directories | grep -qxF "${repo}/packages/new-service" && pass "the stub audited the new root's directory" || fail "audited: $(audited_directories | tr '\n' ' ')"
[[ "$(grep -c ': critical=' <<< "${output}")" == 4 ]] && pass "every root prints, the clean ones after the finding included" || fail "output: ${output}"

echo "--- a lockfile that is not tracked, and a file merely named like one, is not a root"
fixture untracked
add_root app "$(report 0 0 0 0)" 0
mkdir -p "${repo}/scratch" "${repo}/other"
printf 'lockfileVersion: 9.0\n' > "${repo}/scratch/pnpm-lock.yaml"
printf '%s' "$(report 0 9 0 0)" > "${repo}/scratch/stub-report.json"; printf '1' > "${repo}/scratch/stub-status"
printf 'x\n' > "${repo}/other/not-a-pnpm-lock.yaml"
git -C "${repo}" add other/not-a-pnpm-lock.yaml
run_audit
[[ "${status}" == 0 ]] && pass "exit 0" || fail "exit ${status}: ${output}"
[[ "$(audited_directories)" == "${repo}/app" ]] && pass "only the tracked lockfile's root was audited" || fail "audited: $(audited_directories | tr '\n' ' ')"

STUB_CALL_LOG="${work}/real.calls"
: > "${STUB_CALL_LOG}"
export STUB_CALL_LOG

echo "--- --staged audits the index, not the working tree"
# A pnpm whose answer follows the lockfile it is run beside: a lockfile that
# holds the word VULNERABLE reports a high advisory, any other a clean report.
content_bin="${work}/content-bin"
mkdir -p "${content_bin}"
{
	echo '#!/usr/bin/env bash'
	echo 'printf "%s\t%s\n" "${PWD}" "$*" >> "${STUB_CALL_LOG}"'
	printf "if grep -q VULNERABLE pnpm-lock.yaml; then echo '%s'; exit 1; fi\n" "$(report 0 1 0 0)"
	printf "echo '%s'\n" "$(report 0 0 0 0)"
} > "${content_bin}/pnpm"
chmod +x "${content_bin}/pnpm"
run_content_audit() {
	set +e
	output="$(PATH="${content_bin}:${PATH}" bash "${AUDIT}" "$@" "${repo}" 2>"${work}/stderr")"
	status=$?
	set -e
	error_output="$(cat "${work}/stderr")"
}
fixture staged-vulnerable
mkdir -p "${repo}/app"
printf 'lockfileVersion: 9.0\n# VULNERABLE\n' > "${repo}/app/pnpm-lock.yaml"
printf '{"name":"staged"}\n' > "${repo}/app/package.json"
git -C "${repo}" add app/pnpm-lock.yaml app/package.json
printf 'lockfileVersion: 9.0\n' > "${repo}/app/pnpm-lock.yaml"
run_content_audit
[[ "${status}" == 0 ]] && pass "precondition: the working tree's lockfile is clean" || fail "worktree: exit ${status}: ${output} ${error_output}"
run_content_audit --staged
[[ "${status}" == 1 ]] && pass "--staged finds the advisory in the staged lockfile although the working tree is clean" || fail "staged: exit ${status}: ${output} ${error_output}"
[[ "$(tail -n1 "${STUB_CALL_LOG}" | cut -f1)" != "${repo}/app" ]] && pass "--staged audits a copy, not the working tree" || fail "call log: $(cat "${STUB_CALL_LOG}")"
fixture staged-clean
mkdir -p "${repo}/app"
printf 'lockfileVersion: 9.0\n' > "${repo}/app/pnpm-lock.yaml"
git -C "${repo}" add app/pnpm-lock.yaml
printf 'lockfileVersion: 9.0\n# VULNERABLE\n' > "${repo}/app/pnpm-lock.yaml"
run_content_audit
[[ "${status}" == 1 ]] && pass "precondition: the working tree's lockfile is vulnerable" || fail "worktree: exit ${status}: ${output} ${error_output}"
run_content_audit --staged
[[ "${status}" == 0 ]] && pass "--staged passes a clean staged lockfile although the working tree is vulnerable" || fail "staged: exit ${status}: ${output} ${error_output}"
fixture staged-delete
mkdir -p "${repo}/app" "${repo}/tool"
printf 'lockfileVersion: 9.0\n' > "${repo}/app/pnpm-lock.yaml"
printf 'lockfileVersion: 9.0\n# VULNERABLE\n' > "${repo}/tool/pnpm-lock.yaml"
git -C "${repo}" add app/pnpm-lock.yaml tool/pnpm-lock.yaml
git -C "${repo}" -c user.email=t@t -c user.name=t commit --quiet -m fixture
git -C "${repo}" rm --quiet --cached tool/pnpm-lock.yaml
run_content_audit --staged
[[ "${status}" == 0 ]] && pass "--staged skips a lockfile staged for deletion" || fail "staged delete: exit ${status}: ${output} ${error_output}"
grep -qF 'app: critical=0' <<< "${output}" && pass "precondition: the remaining root was audited" || fail "output: ${output}"

echo "--- usage"
fixture usage
add_root app "$(report 0 0 0 0)" 0
run_audit --threshold bogus
[[ "${status}" == 64 ]] && pass "an unknown threshold is exit 64" || fail "bogus threshold: exit ${status}"
[[ ! -s "${STUB_CALL_LOG}" ]] && pass "no audit ran" || fail "call log: $(cat "${STUB_CALL_LOG}")"
run_audit --no-such-option
[[ "${status}" == 64 ]] && pass "an unknown option is exit 64" || fail "unknown option: exit ${status}"

echo
echo "${passed} passed, ${failed} failed"
[[ "${failed}" -eq 0 ]]
