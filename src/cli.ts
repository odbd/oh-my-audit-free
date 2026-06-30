#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// oh-my-audit-free CLI — scan a directory locally and print a security score
// with actionable findings. Nothing leaves your machine.
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import {
	analyzeScoreFiles,
	runOptionalExternalScans,
	type ScoreFinding,
	type ScoreInputFile,
	type ScoreProcessorResult,
} from "./index.js";

const IGNORE_DIRS = new Set([
	".git",
	"node_modules",
	"dist",
	"build",
	".svelte-kit",
	".next",
	".turbo",
	"coverage",
	"vendor",
	"__pycache__",
	".venv",
	"venv",
	".gradle",
	"target",
]);
const MAX_FILES = 20_000;
const MAX_FILE_BYTES = 1024 * 1024; // 1MB per file
const MAX_TOTAL_BYTES = 200 * 1024 * 1024; // 200MB total

type Format = "pretty" | "json" | "sarif";
type Severity = ScoreFinding["severity"];
const SEVERITY_RANK: Record<Severity, number> = {
	critical: 4,
	high: 3,
	medium: 2,
	low: 1,
	info: 0,
};

type Flags = {
	path: string;
	format: Format;
	semgrep: boolean;
	gitleaks: boolean;
	osv: boolean;
	failOn: Severity | null;
};

function parseArgs(argv: string[]): Flags {
	const flags: Flags = {
		path: ".",
		format: "pretty",
		semgrep: true,
		gitleaks: true,
		osv: true,
		failOn: null,
	};
	let pathSet = false;
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--json") flags.format = "json";
		else if (arg === "--sarif") flags.format = "sarif";
		else if (arg === "--format") flags.format = argv[++i] as Format;
		else if (arg === "--no-semgrep") flags.semgrep = false;
		else if (arg === "--no-gitleaks") flags.gitleaks = false;
		else if (arg === "--no-osv") flags.osv = false;
		else if (arg === "--fail-on") flags.failOn = argv[++i] as Severity;
		else if (arg === "-h" || arg === "--help") {
			printHelp();
			process.exit(0);
		} else if (!arg.startsWith("-") && !pathSet) {
			flags.path = arg;
			pathSet = true;
		}
	}
	return flags;
}

function printHelp() {
	process.stdout.write(
		`oh-my-audit — local security scan (secrets, SAST, vulnerable deps)

Usage: ohmyaudit scan [path] [options]

Options:
  --json              Output the full result as JSON
  --sarif             Output SARIF 2.1.0 (for GitHub code scanning / CI)
  --fail-on <sev>     Exit 1 if any finding >= severity (critical|high|medium|low)
  --no-semgrep        Skip the semgrep (SAST) scan
  --no-gitleaks       Skip the gitleaks (secrets) scan
  --no-osv            Skip the osv-scanner (dependencies) scan
  -h, --help          Show this help

Requires gitleaks, semgrep, and osv-scanner on PATH (or use the Docker image).
Runs entirely locally — your source never leaves your machine.
`,
	);
}

async function readSourceTree(root: string): Promise<ScoreInputFile[]> {
	const files: ScoreInputFile[] = [];
	let total = 0;
	async function walk(dir: string) {
		const entries = await readdir(dir, { withFileTypes: true });
		for (const entry of entries) {
			if (files.length >= MAX_FILES) return;
			const abs = join(dir, entry.name);
			if (entry.isDirectory()) {
				if (IGNORE_DIRS.has(entry.name)) continue;
				await walk(abs);
			} else if (entry.isFile()) {
				const info = await stat(abs).catch(() => null);
				if (!info || info.size > MAX_FILE_BYTES) continue;
				if (total + info.size > MAX_TOTAL_BYTES) continue;
				const buf = await readFile(abs).catch(() => null);
				if (!buf) continue;
				// Skip binaries: a NUL byte in the first 8KB is a strong signal.
				if (buf.subarray(0, 8192).includes(0)) continue;
				total += info.size;
				files.push({
					path: relative(root, abs).split("\\").join("/"),
					content: buf.toString("utf8"),
				});
			}
		}
	}
	await walk(root);
	return files;
}

function scanEnv(flags: Flags): Record<string, string | undefined> {
	return {
		...process.env,
		SEMGREP_ENABLED: flags.semgrep ? "true" : "false",
		SEMGREP_COMMAND: process.env.SEMGREP_COMMAND || "semgrep",
		GITLEAKS_ENABLED: flags.gitleaks ? "true" : "false",
		GITLEAKS_COMMAND: process.env.GITLEAKS_COMMAND || "gitleaks",
		OSV_ENABLED: flags.osv ? "true" : "false",
		OSV_COMMAND: process.env.OSV_COMMAND || "osv-scanner",
	};
}

function severityLevel(sev: Severity): "error" | "warning" | "note" {
	if (sev === "critical" || sev === "high") return "error";
	if (sev === "medium") return "warning";
	return "note";
}

function splitFileAndLine(file: string | undefined): {
	uri: string | null;
	line: number | null;
} {
	if (!file) return { uri: null, line: null };
	const m = /^(.*):(\d+)$/.exec(file);
	if (m) return { uri: m[1], line: Number(m[2]) };
	return { uri: file, line: null };
}

function toSarif(result: ScoreProcessorResult): string {
	const findings = result.internalFindings;
	const ruleIds = new Map<string, ScoreFinding>();
	for (const f of findings) {
		const id = f.ruleId || `${f.source}/${f.category}`;
		if (!ruleIds.has(id)) ruleIds.set(id, f);
	}
	const sarif = {
		$schema:
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "oh-my-audit",
						informationUri: "https://ohmyaudit.app",
						rules: Array.from(ruleIds.entries()).map(([id, f]) => ({
							id,
							name: f.title,
							shortDescription: { text: f.title },
							helpUri: "https://ohmyaudit.app",
							properties: { category: f.category, "security-severity": String(SEVERITY_RANK[f.severity] * 2.5) },
						})),
					},
				},
				results: findings.map((f) => {
					const { uri, line } = splitFileAndLine(f.file);
					return {
						ruleId: f.ruleId || `${f.source}/${f.category}`,
						level: severityLevel(f.severity),
						message: {
							text: `${f.title}${f.remediationHint ? ` — ${f.remediationHint}` : ""}`,
						},
						...(uri
							? {
									locations: [
										{
											physicalLocation: {
												artifactLocation: { uri },
												...(line ? { region: { startLine: line } } : {}),
											},
										},
									],
								}
							: {}),
					};
				}),
			},
		],
	};
	return JSON.stringify(sarif, null, 2);
}

const COLORS = {
	reset: "\x1b[0m",
	bold: "\x1b[1m",
	dim: "\x1b[2m",
	red: "\x1b[31m",
	yellow: "\x1b[33m",
	green: "\x1b[32m",
	cyan: "\x1b[36m",
};
function color(s: string, c: keyof typeof COLORS): string {
	return process.stdout.isTTY ? `${COLORS[c]}${s}${COLORS.reset}` : s;
}

function printPretty(result: ScoreProcessorResult, fileCount: number) {
	const out: string[] = [];
	const scoreColor =
		result.score >= 80 ? "green" : result.score >= 50 ? "yellow" : "red";
	out.push("");
	out.push(
		`${color("oh-my-audit", "cyan")}  ${color(`${result.score}/100`, scoreColor)}  ${color(result.riskLevel, "dim")}  ${color(`(${fileCount} files)`, "dim")}`,
	);
	out.push("");

	const findings = result.internalFindings;
	const isSecret = (f: ScoreFinding) =>
		f.source === "gitleaks" || f.category === "secret";
	const secrets = findings.filter(isSecret);
	const highImpact = findings.filter(
		(f) => !isSecret(f) && (f.severity === "critical" || f.severity === "high"),
	);
	const rest = findings.length - secrets.length - highImpact.length;

	if (secrets.length > 0) {
		out.push(color(`⚠ ${secrets.length} leaked secret(s) — rotate now`, "red"));
		for (const f of secrets) out.push(...formatFinding(f));
		out.push("");
	}
	if (highImpact.length > 0) {
		out.push(color(`Critical & high-risk findings (${highImpact.length})`, "bold"));
		for (const f of highImpact) out.push(...formatFinding(f));
		out.push("");
	}
	if (findings.length === 0) {
		out.push(color("No findings. Looks clean.", "green"));
		out.push("");
	} else if (rest > 0) {
		out.push(color(`+ ${rest} more medium/low-risk finding(s).`, "dim"));
		out.push("");
	}
	out.push(
		color(
			"Automated analysis can include false positives — verify before acting.",
			"dim",
		),
	);
	out.push(
		color(
			"Shareable verified report & continuous monitoring: https://ohmyaudit.app",
			"dim",
		),
	);
	out.push("");
	process.stdout.write(out.join("\n"));
}

function formatFinding(f: ScoreFinding): string[] {
	const sevTag = `[${f.severity}]`;
	const loc = f.file ? color(` ${f.file}`, "dim") : "";
	const lines = [`  ${color(sevTag, f.severity === "critical" || f.severity === "high" ? "red" : "yellow")} ${f.title}${loc}`];
	if (f.remediationHint) lines.push(color(`      fix: ${f.remediationHint}`, "dim"));
	const refs = [...(f.cwe ?? []), ...(f.owasp ?? [])];
	if (refs.length > 0) lines.push(color(`      ref: ${refs.join(", ")}`, "dim"));
	return lines;
}

async function main() {
	const argv = process.argv.slice(2);
	// Allow both `ohmyaudit scan .` and `ohmyaudit .`
	const rest = argv[0] === "scan" ? argv.slice(1) : argv;
	const flags = parseArgs(rest);

	const files = await readSourceTree(flags.path);
	if (files.length === 0) {
		process.stderr.write(`No source files found under ${flags.path}\n`);
		process.exit(2);
	}

	let external = {};
	try {
		external = await runOptionalExternalScans(files, scanEnv(flags), {});
	} catch (err) {
		process.stderr.write(
			`Warning: external scanners failed (${err instanceof Error ? err.message : "unknown"}). ` +
				`Ensure gitleaks/semgrep/osv-scanner are installed. Continuing with heuristics only.\n`,
		);
	}
	const result = analyzeScoreFiles(files, external);

	if (flags.format === "json") {
		process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
	} else if (flags.format === "sarif") {
		process.stdout.write(`${toSarif(result)}\n`);
	} else {
		printPretty(result, files.length);
	}

	if (flags.failOn) {
		const threshold = SEVERITY_RANK[flags.failOn];
		const hit = result.internalFindings.some(
			(f) => SEVERITY_RANK[f.severity] >= threshold,
		);
		if (hit) process.exit(1);
	}
}

main().catch((err) => {
	process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
	process.exit(2);
});
