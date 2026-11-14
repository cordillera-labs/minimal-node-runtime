#!/usr/bin/env bash
#
# dependency-advisory-audit.sh — run `pnpm audit` in every lockfile root of the
# repository and fail when any root reports an advisory at or above a severity
# threshold.
#
# WHY THIS EXISTS
# Nothing in CI covered dependency advisories. An advisory lands against a
# lockfile that did not change, so a repository can hold dozens of known
# vulnerabilities and every pull request still passes. This script is the gate
# that closes that gap; dependency-advisory-audit.test.sh is its
# self-test. The audit-deps composite action runs it on a repository checkout.
#
# USAGE
#   dependency-advisory-audit.sh [--threshold LEVEL] [--staged] [REPO_ROOT]
#
#   LEVEL        low | moderate | high | critical. Default: moderate. An advisory at
#                LEVEL or above is a finding; a lower one is printed and passes.
#   --staged     audit the index, not the working tree. Each root's staged
#                pnpm-lock.yaml, package.json, pnpm-workspace.yaml and .npmrc are
#                written to a temporary directory, and `pnpm audit` runs there. The
#                pre-commit hook passes it, so the hook judges the tree the commit
#                records even when a dependency file also has unstaged edits.
#   REPO_ROOT    the repository to audit. Default: the repository holding this
#                script.
#
# WHAT A ROOT IS
# A lockfile root is the directory of every tracked `pnpm-lock.yaml`, read from
# `git ls-files`. A new root joins the audit when its lockfile is committed, with
# no edit here. A repository with no tracked lockfile faults, because an audit of
# zero roots would pass without having read anything.
#
# EXIT CODES — a finding and a fault are different results
#   0    every root was audited and none holds an advisory at or above LEVEL
#   1    FINDING: at least one root holds an advisory at or above LEVEL
#   64   usage: an unknown option, or a LEVEL outside the four names
#   69   FAULT: the audit could not read a result for at least one root — no
#        network, a registry error, a timeout, a response that is not an audit
#        report, or no tracked lockfile. The roots that did answer are still
#        printed. A fault outranks a finding, because a run that could not
#        finish its reading proves nothing about the roots it skipped.
# `pnpm audit` itself exits 1 for both a finding and a registry error, so this
# script never reads that status as a verdict. It reads the report: counts in
# `metadata.vulnerabilities` are a result, and anything else is a fault.
#
# OUTPUT
# One line per root on stdout: `<root>: critical=N high=N moderate=N low=N`,
# then each advisory's package, installed version, GHSA/URL, vulnerable range,
# and recommended patched range (when available). The summary line is last.
# Faults and diagnostics go to stderr.
set -euo pipefail

EXIT_FINDING=1
EXIT_USAGE=64
EXIT_FAULT=69
# One registry answer must arrive inside this many seconds. A hung request
# otherwise holds the whole job until the workflow timeout.
AUDIT_TIMEOUT_SECONDS="${DEPENDENCY_AUDIT_TIMEOUT_SECONDS:-120}"

usage() {
	cat >&2 <<'EOF'
usage: dependency-advisory-audit.sh [--threshold low|moderate|high|critical] [--staged] [REPO_ROOT]
EOF
}

threshold="moderate"
audit_staged=0
repo_root=""
while [[ $# -gt 0 ]]; do
	case "$1" in
		--threshold)
			[[ $# -ge 2 ]] || { usage; exit "${EXIT_USAGE}"; }
			threshold="$2"
			shift 2
			;;
		--staged)
			audit_staged=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		-*)
			usage
			exit "${EXIT_USAGE}"
			;;
		*)
			[[ -z "${repo_root}" ]] || { usage; exit "${EXIT_USAGE}"; }
			repo_root="$1"
			shift
			;;
	esac
done

case "${threshold}" in
	low | moderate | high | critical) ;;
	*)
		echo "dependency-advisory-audit: unknown threshold '${threshold}'" >&2
		usage
		exit "${EXIT_USAGE}"
		;;
esac

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${repo_root:-$(cd "${script_directory}/.." && pwd)}"
cd "${repo_root}"

# summarize_report — read an audit report on stdin and print its four counts as
# `critical high moderate low` on line one followed by actionable diagnostics.
# Fail when the input is not an audit report. A report holds `metadata.vulnerabilities` with a count for
# each severity and an `advisories` object; a registry error holds `error`
# instead, and a proxy page or a truncated body is not JSON at all.
#
# The counts come from `advisories`, one per advisory by its severity. pnpm drops
# an advisory listed in `auditConfig.ignoreGhsas` (pnpm-workspace.yaml) from
# `advisories` but still counts it in `metadata.vulnerabilities`, so the metadata
# total would fail the gate on an advisory the repository has reviewed and
# exempted. `metadata.vulnerabilities` stays required: it marks the input as a
# report.
summarize_report() {
	node -e '
		const chunks = [];
		process.stdin.on("data", (chunk) => chunks.push(chunk));
		process.stdin.on("end", () => {
			let report;
			try {
				report = JSON.parse(Buffer.concat(chunks).toString("utf8"));
			} catch {
				process.exit(1);
			}
			const counts = report?.metadata?.vulnerabilities;
			const severities = ["critical", "high", "moderate", "low"];
			const valid = report?.error === undefined
				&& counts !== null && typeof counts === "object"
				&& severities.every((severity) => Number.isInteger(counts[severity]) && counts[severity] >= 0);
			const advisories = report?.advisories;
			if (!valid || advisories === null || typeof advisories !== "object") process.exit(1);
			const reported = Object.fromEntries(severities.map((severity) => [severity, 0]));
			for (const advisory of Object.values(advisories)) {
				// `info` sits below every threshold, as in the metadata. Any other
				// unknown severity is a report this script cannot read, not a pass.
				if (advisory?.severity === "info") continue;
				if (!severities.includes(advisory?.severity)) process.exit(1);
				reported[advisory.severity] += 1;
			}
			console.log(severities.map((severity) => reported[severity]).join(" "));
		// Registry strings are not trusted output; remove control characters.
		const printable = (value) => typeof value === "string"
			? value.replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim().slice(0, 240)
			: "";
		const severityOrder = { critical: 0, high: 1, moderate: 2, low: 3 };
		const details = Object.entries(advisories).map(([key, advisory]) => {
			const severity = advisory.severity;
			const pkg = printable(advisory.module_name) || "(unknown package)";
			const installed = Array.isArray(advisory.findings)
				? [...new Set(advisory.findings.map((finding) => printable(finding?.version)).filter(Boolean))].join(", ") || "not reported"
				: "not reported";
			const url = printable(advisory.url);
			const id = (url.match(/GHSA-[a-z0-9-]+/i) || [])[0]
				|| (advisory.id == null ? "" : printable(String(advisory.id)))
				|| printable(key);
			const title = printable(advisory.title) || "Security advisory";
			const vulnerable = printable(advisory.vulnerable_versions) || "not reported";
			const patched = printable(advisory.patched_versions);
			const recommendation = patched
				? "Upgrade " + pkg + " to a release satisfying " + patched + " (use an override if transitive)"
				: "No published patched release for " + pkg + "; assess exposure or alternatives";
			return {
				severity, pkg, id,
				lines: [
					"  " + severity.toUpperCase() + " " + pkg + " (installed: " + installed + ") [" + id + "] - " + title,
					"    Vulnerable: " + vulnerable + "; patched range: " + (patched || "none published"),
					"    Recommended: " + recommendation,
					...(url ? ["    Advisory: " + url] : []),
				],
			};
		}).sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4)
			|| a.pkg.localeCompare(b.pkg) || a.id.localeCompare(b.id));
		for (const item of details) for (const line of item.lines) console.log(line);
		});
	'
}

mapfile -t lockfiles < <(git ls-files -- '*pnpm-lock.yaml' | grep -E '(^|/)pnpm-lock\.yaml$' || true)
if [[ "${#lockfiles[@]}" -eq 0 ]]; then
	echo "dependency-advisory-audit: no tracked pnpm-lock.yaml under ${repo_root}; an audit of zero roots would pass without reading anything" >&2
	exit "${EXIT_FAULT}"
fi

# at_or_above LEVEL CRITICAL HIGH MODERATE LOW — the number of advisories at LEVEL or above.
at_or_above() {
	local level="$1" critical_count="$2" high_count="$3" moderate_count="$4" low_count="$5"
	case "${level}" in
		critical) echo "${critical_count}" ;;
		high) echo $((critical_count + high_count)) ;;
		moderate) echo $((critical_count + high_count + moderate_count)) ;;
		low) echo $((critical_count + high_count + moderate_count + low_count)) ;;
	esac
}

# staged_root_copy DIRECTORY — write the staged dependency files of the root at
# DIRECTORY to a fresh temporary directory, and print that directory. The index
# is what `git ls-files` lists, so a lockfile staged for deletion is no root,
# and a staged new lockfile is one.
STAGED_DEPENDENCY_FILES=(pnpm-lock.yaml package.json pnpm-workspace.yaml .npmrc)
staged_copies=()
cleanup_staged_copies() { (( ${#staged_copies[@]} == 0 )) || rm -rf "${staged_copies[@]}"; }
trap cleanup_staged_copies EXIT
staged_root_copy() {
	local directory="$1" copy_directory dependency_file staged_path
	copy_directory="$(mktemp -d)"
	for dependency_file in "${STAGED_DEPENDENCY_FILES[@]}"; do
		staged_path="${dependency_file}"
		[[ "${directory}" == "." ]] || staged_path="${directory}/${dependency_file}"
		if git cat-file -e ":${staged_path}" 2> /dev/null; then
			git show ":${staged_path}" > "${copy_directory}/${dependency_file}"
		fi
	done
	printf '%s' "${copy_directory}"
}

finding_roots=()
fault_roots=()
for lockfile in "${lockfiles[@]}"; do
	lockfile_directory="$(dirname "${lockfile}")"
	root_label="${lockfile_directory}"
	[[ "${root_label}" != "." ]] || root_label="(repository root)"

	# `pnpm audit` exits 1 for a finding and for a registry error alike, so its
	# status is captured and set aside; the report decides.
	audit_stdout=""
	audit_stderr_file="$(mktemp)"
	audit_status=0
	audit_directory="${lockfile_directory}"
	if (( audit_staged )); then
		audit_directory="$(staged_root_copy "${lockfile_directory}")"
		staged_copies+=("${audit_directory}")
	fi
	audit_stdout="$(cd "${audit_directory}" && timeout "${AUDIT_TIMEOUT_SECONDS}" pnpm audit --json 2> "${audit_stderr_file}")" || audit_status=$?

	if ! counts="$(printf '%s' "${audit_stdout}" | summarize_report)"; then
		echo "${root_label}: FAULT — no audit report (pnpm audit exit ${audit_status})"
		{
			echo "dependency-advisory-audit: ${root_label} returned no audit report. Output follows."
			# A here-string, not `printf | head`: head exits after 600 bytes, and a
			# longer response would kill the writer with SIGPIPE under pipefail.
			head -c 600 <<<"${audit_stdout}"
			head -c 600 "${audit_stderr_file}"
		} >&2
		rm -f "${audit_stderr_file}"
		fault_roots+=("${root_label}")
		continue
	fi
	rm -f "${audit_stderr_file}"

	# Counts are machine-readable; remaining lines are display-only.
	count_line="${counts%%$'\n'*}"
	read -r critical_count high_count moderate_count low_count <<< "${count_line}"
	blocking_count="$(at_or_above "${threshold}" "${critical_count}" "${high_count}" "${moderate_count}" "${low_count}")"
	printf '%s: critical=%s high=%s moderate=%s low=%s\n' "${root_label}" "${critical_count}" "${high_count}" "${moderate_count}" "${low_count}"
	if [[ "${counts}" != "${count_line}" ]]; then
		printf '%s\n' "${counts#*$'\n'}"
	fi
	if [[ "${blocking_count}" -gt 0 ]]; then
		echo "  FINDING — ${blocking_count} advisory(ies) at ${threshold} or above"
		finding_roots+=("${root_label}")
	else
		echo "  ok — none at ${threshold} or above"
	fi
done

echo "dependency-advisory-audit: ${#lockfiles[@]} root(s), threshold ${threshold}, ${#finding_roots[@]} with findings, ${#fault_roots[@]} faulted"
if [[ "${#fault_roots[@]}" -gt 0 ]]; then
	echo "dependency-advisory-audit: FAULT — no result for: ${fault_roots[*]}" >&2
	exit "${EXIT_FAULT}"
fi
if [[ "${#finding_roots[@]}" -gt 0 ]]; then
	echo "dependency-advisory-audit: FINDING — advisories at ${threshold} or above in: ${finding_roots[*]}" >&2
	exit "${EXIT_FINDING}"
fi
exit 0
