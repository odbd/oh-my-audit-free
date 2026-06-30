import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { promisify } from "node:util";
import { inflateRawSync } from "node:zlib";

const execFileAsync = promisify(execFile);

export function positiveIntegerOrDefault(
	value: number | undefined,
	fallback: number,
	min: number,
) {
	if (value === undefined || !Number.isFinite(value)) return fallback;
	return Math.max(min, Math.floor(value));
}

// Scanners run untrusted user code. They must NOT inherit the process
// environment, which holds high-value secrets (DATABASE_URL, R2 keys,
// RESEND_API_KEY, GITHUB_APP_PRIVATE_KEY_BASE64, ...). A scanner RCE on a
// malicious repo would otherwise exfiltrate every credential. We pass only the
// handful of vars a scanner legitimately needs to run and reach its update
// servers over TLS.
const SCANNER_ENV_ALLOWLIST = [
	"PATH",
	"HOME",
	"TMPDIR",
	"TMP",
	"TEMP",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"NODE_EXTRA_CA_CERTS",
] as const;

export function buildScannerEnv(
	baseEnv: NodeJS.ProcessEnv,
	extra: Record<string, string> = {},
): NodeJS.ProcessEnv {
	const safe: NodeJS.ProcessEnv = {};
	for (const key of SCANNER_ENV_ALLOWLIST) {
		const value = baseEnv[key];
		if (typeof value === "string" && value.length > 0) safe[key] = value;
	}
	return { ...safe, ...extra };
}

export type ScoreInputFile = {
	path: string;
	content: string;
};

export type ScoreFinding = {
	source: "heuristic" | "semgrep" | "sarif" | "gitleaks" | "osv";
	ruleId?: string;
	category:
		| "auth"
		| "payment"
		| "secret"
		| "dependency"
		| "upload"
		| "config"
		| "data-access";
	severity: "critical" | "high" | "medium" | "low" | "info";
	title: string;
	evidence: string;
	file?: string;
	confidence: "high" | "medium" | "low";
	cwe?: string[];
	owasp?: string[];
	remediationHint?: string;
};

export type ScoreProcessorResult = {
	score: number;
	riskLevel: string;
	launchBlockerCount: number;
	highRiskCount: number;
	mediumRiskCount: number;
	scanCoverage: Record<string, unknown>;
	scannerResults?: Record<string, unknown>;
	publicSummary: {
		headline: string;
		reasons: string[];
		recommendedPlan: "Quick Scan" | "Full Audit" | "Launch Audit";
	};
	internalFindings: ScoreFinding[];
};

type ScoreBreakdown = {
	modelVersion: string;
	baseScore: 100;
	score: number;
	rawPenalty: number;
	cappedPenalty: number;
	zeroScoreReason?: string;
	sourceCaps: Record<ScoreFinding["source"], number>;
	bySource: Record<
		string,
		{
			findingCount: number;
			rawPenalty: number;
			cappedPenalty: number;
			cap: number;
			severityCounts: Record<string, number>;
		}
	>;
	bySeverity: Record<string, { findingCount: number; penalty: number }>;
	byCategory: Record<
		string,
		{
			findingCount: number;
			rawPenalty: number;
			severityCounts: Record<string, number>;
		}
	>;
};

type ZipExtractionLimits = {
	maxFiles: number;
	maxFileBytes: number;
	maxTotalBytes: number;
};

export type ProcessOptions = {
	loadUpload?: (uploadRef: string) => Promise<Buffer>;
	limits?: Partial<ZipExtractionLimits>;
	now?: () => string;
	logger?: Pick<Console, "log" | "error">;
	maxAttempts?: number;
	staleProcessingMs?: number;
	semgrep?: false | Partial<SemgrepScanOptions>;
	gitleaks?: false | Partial<GitleaksScanOptions>;
	osv?: false | Partial<OsvScanOptions>;
};

type ExternalScanOutcome = {
	findings: ScoreFinding[];
	coverage?: Record<string, unknown>;
};

type FindingIgnoreRule = {
	source?: ScoreFinding["source"];
	ruleId?: string;
	id?: string;
	path?: string;
	category?: ScoreFinding["category"];
	severity?: ScoreFinding["severity"];
	reason?: string;
	expiresAt?: string;
};

type FindingIgnorePolicy = {
	rules: FindingIgnoreRule[];
	parseErrors: string[];
};

export type AnalysisContext = {
	files: ScoreInputFile[];
	filePaths: string[];
	allContent: string;
	filesByPath: Map<string, ScoreInputFile>;
};

export type ScoreRule = {
	id: string;
	name: string;
	run(context: AnalysisContext): ScoreFinding[];
};

export type ScoreAnalysisOptions = {
	externalFindings?: ScoreFinding[];
	externalScanCoverage?: Record<string, unknown>;
	externalScannerResults?: Record<string, unknown>;
};

export type SemgrepScanOptions = {
	enabled: boolean;
	command: string;
	configs: string[];
	extraArgs: string[];
	proMode: "off" | "pro" | "intrafile" | "path-sensitive";
	secretsEnabled: boolean;
	timeoutMs: number;
	maxFindings: number;
};

export type GitleaksScanOptions = {
	enabled: boolean;
	command: string;
	extraArgs: string[];
	timeoutMs: number;
	maxFindings: number;
};

export type OsvScanOptions = {
	enabled: boolean;
	command: string;
	extraArgs: string[];
	timeoutMs: number;
	maxFindings: number;
};

export type ScoreFailureTransition = {
	status: "queued" | "failed";
	startedAt: null;
	completedAt: string | null;
};

export const DEFAULT_SCORE_MAX_ATTEMPTS = 3;
export const DEFAULT_SCORE_STALE_PROCESSING_MS = 15 * 60 * 1000;

const DEFAULT_LIMITS: ZipExtractionLimits = {
	maxFiles: 500,
	maxFileBytes: 256 * 1024,
	maxTotalBytes: 3 * 1024 * 1024,
};

export const SCORE_MODEL_VERSION = "2026-05-27.2";

const SOURCE_PENALTY_CAPS: Record<ScoreFinding["source"], number> = {
	heuristic: 60,
	gitleaks: 40,
	semgrep: 35,
	osv: 25,
	sarif: 35,
};

const TEXT_EXTENSIONS = new Set([
	".ts",
	".tsx",
	".js",
	".jsx",
	".svelte",
	".vue",
	".html",
	".htm",
	".jinja",
	".j2",
	".hbs",
	".handlebars",
	".mustache",
	".py",
	".rb",
	".go",
	".rs",
	".java",
	".kt",
	".php",
	".cs",
	".json",
	".md",
	".yml",
	".yaml",
	".toml",
	".env",
	".txt",
	".sql",
	".prisma",
	".graphql",
	".sh",
	".bash",
	".zsh",
	".fish",
	".ps1",
	".tf",
	".tfvars",
	".ini",
	".conf",
	".cfg",
	".properties",
	".xml",
]);

const IMPORTANT_FILE_NAMES = new Set([
	".env",
	".env.local",
	".env.production",
	".npmrc",
	".pypirc",
	".netrc",
	".oh-my-audit-ignore",
	"dockerfile",
	"containerfile",
	"compose.yaml",
	"compose.yml",
	"docker-compose.yaml",
	"docker-compose.yml",
	"makefile",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"bun.lockb",
	"requirements.txt",
	"poetry.lock",
	"go.sum",
	"cargo.lock",
]);

const EXCLUDED_SEGMENTS = new Set([
	"node_modules",
	".git",
	"dist",
	"build",
	".svelte-kit",
	".next",
	".nuxt",
	"coverage",
]);

export function extractScoreAnalysisInputsFromZip(
	zip: Buffer,
	limitsInput: Partial<ZipExtractionLimits> = {},
) {
	const limits = { ...DEFAULT_LIMITS, ...limitsInput };
	const entries = readZipEntries(zip);
	const files: ScoreInputFile[] = [];
	const skipped: string[] = [];
	let totalBytes = 0;

	for (const entry of entries) {
		if (files.length >= limits.maxFiles) {
			skipped.push(`${entry.path}: max file count reached`);
			continue;
		}

		const safePath = normalizeSafeZipPath(entry.path);
		if (!safePath) {
			skipped.push(`${entry.path}: unsafe path`);
			continue;
		}
		if (entry.directory || shouldExcludePath(safePath)) {
			skipped.push(`${safePath}: excluded path`);
			continue;
		}
		if (!shouldReadTextFile(safePath)) {
			skipped.push(`${safePath}: unsupported file type`);
			continue;
		}
		// Cheap early reject on the declared size (untrusted, but avoids
		// inflating obvious oversizers). The real enforcement happens on the
		// decompressed bytes below.
		if (entry.uncompressedSize > limits.maxFileBytes) {
			skipped.push(`${safePath}: file too large`);
			continue;
		}

		let data: Buffer;
		try {
			data = readZipEntryData(zip, entry, limits.maxFileBytes);
		} catch {
			skipped.push(`${safePath}: unable to decompress within limits`);
			continue;
		}
		if (data.length > limits.maxFileBytes) {
			skipped.push(`${safePath}: file too large`);
			continue;
		}
		if (totalBytes + data.length > limits.maxTotalBytes) {
			skipped.push(`${safePath}: total size limit reached`);
			continue;
		}
		if (!isLikelyText(data)) {
			skipped.push(`${safePath}: binary file`);
			continue;
		}

		files.push({ path: safePath, content: data.toString("utf8") });
		totalBytes += data.length;
	}

	return { files, skipped };
}

export function analyzeScoreFiles(
	files: ScoreInputFile[],
	options: ScoreAnalysisOptions = {},
): ScoreProcessorResult {
	const context = createAnalysisContext(files);
	const ignorePolicy = parseFindingIgnorePolicy(context);
	const initialFindings = dedupeFindings([
		...runScoreRules(context),
		...(options.externalFindings ?? []),
	]);
	const { findings: findingsAfterIgnore, ignored } = applyFindingIgnorePolicy(
		initialFindings,
		ignorePolicy,
	);
	const { findings, adjustments: scoringAdjustments } =
		refineFindingsForScoring(findingsAfterIgnore);
	const scoreBreakdown = calculateScoreBreakdown(findings);
	const score = scoreBreakdown.score;
	const riskLevel = getRiskLevel(score, findings);
	const launchBlockerCount = findings.filter(
		(finding) => finding.severity === "critical",
	).length;
	const highRiskCount = findings.filter(
		(finding) => finding.severity === "high",
	).length;
	const mediumRiskCount = findings.filter(
		(finding) => finding.severity === "medium",
	).length;
	const categories = Array.from(
		new Set(findings.map((finding) => finding.category)),
	);
	const lowerAllContent = context.allContent.toLowerCase();
	const scannerResults = options.externalScannerResults
		? attachScannerScoreImpact(options.externalScannerResults, scoreBreakdown)
		: undefined;

	return {
		score,
		riskLevel,
		launchBlockerCount,
		highRiskCount,
		mediumRiskCount,
		scanCoverage: {
			filesScanned: files.length,
			categories,
			rulesRun: SCORE_RULES.map((rule) => rule.id),
			...(options.externalScanCoverage
				? { externalScanners: options.externalScanCoverage }
				: {}),
			scoreBreakdown,
			scoringAdjustments,
			ignoreSummary: {
				rulesLoaded: ignorePolicy.rules.length,
				ignoredFindings: ignored.length,
				parseErrors: ignorePolicy.parseErrors,
			},
			detectedSignals: {
				auth: /auth|login|session|user/.test(lowerAllContent),
				payment: /payment|checkout|polar|stripe|webhook|toss/.test(
					lowerAllContent,
				),
				upload: /upload|formdata|file|multipart/.test(lowerAllContent),
				admin: context.filePaths.some(isAdminRoutePath),
				secrets: findings.some((finding) => finding.category === "secret"),
			},
		},
		...(scannerResults ? { scannerResults } : {}),
		publicSummary: {
			headline: buildHeadline(score, findings),
			reasons: buildSummaryReasons(findings),
			recommendedPlan: chooseRecommendedPlan(findings),
		},
		internalFindings: findings,
	};
}

export function createAnalysisContext(
	files: ScoreInputFile[],
): AnalysisContext {
	return {
		files,
		filePaths: files.map((file) => file.path),
		allContent: files.map((file) => file.content).join("\n"),
		filesByPath: new Map(files.map((file) => [file.path, file])),
	};
}

export function runScoreRules(
	context: AnalysisContext,
	rules: ScoreRule[] = SCORE_RULES,
) {
	return dedupeFindings(rules.flatMap((rule) => rule.run(context)));
}

function parseFindingIgnorePolicy(
	context: AnalysisContext,
): FindingIgnorePolicy {
	const policyFile = context.filesByPath.get(".oh-my-audit-ignore");
	if (!policyFile) return { rules: [], parseErrors: [] };
	const content = policyFile.content.trim();
	if (!content) return { rules: [], parseErrors: [] };

	try {
		const parsed = JSON.parse(content) as unknown;
		const rules = Array.isArray(parsed)
			? parsed
			: isRecord(parsed) && Array.isArray(parsed.ignore)
				? parsed.ignore
				: [];
		return {
			rules: rules.filter(isRecord).map(normalizeIgnoreRule),
			parseErrors: [],
		};
	} catch {
		return parseLineBasedIgnorePolicy(content);
	}
}

function parseLineBasedIgnorePolicy(content: string): FindingIgnorePolicy {
	const rules: FindingIgnoreRule[] = [];
	const parseErrors: string[] = [];
	for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
		const line = rawLine.trim();
		if (!line || line.startsWith("#")) continue;
		const parts = line.split(/\s+/);
		const rule: FindingIgnoreRule = {};
		for (const part of parts) {
			const [key, ...valueParts] = part.split("=");
			const value = valueParts.join("=");
			if (!key || !value) continue;
			assignIgnoreRuleField(rule, key, value);
		}
		if (Object.keys(rule).length === 0) {
			parseErrors.push(`Line ${index + 1}: expected key=value entries.`);
			continue;
		}
		rules.push(rule);
	}
	return { rules, parseErrors };
}

function normalizeIgnoreRule(
	value: Record<string, unknown>,
): FindingIgnoreRule {
	const rule: FindingIgnoreRule = {};
	for (const [key, rawValue] of Object.entries(value)) {
		const string = stringValue(rawValue);
		if (string) assignIgnoreRuleField(rule, key, string);
	}
	return rule;
}

function assignIgnoreRuleField(
	rule: FindingIgnoreRule,
	key: string,
	value: string,
) {
	const normalizedKey = key.toLowerCase();
	if (normalizedKey === "source" && isScoreFindingSource(value))
		rule.source = value;
	else if (normalizedKey === "ruleid" || normalizedKey === "rule")
		rule.ruleId = value;
	else if (normalizedKey === "id") rule.id = value;
	else if (normalizedKey === "path" || normalizedKey === "file")
		rule.path = value;
	else if (normalizedKey === "category" && isScoreFindingCategory(value))
		rule.category = value;
	else if (normalizedKey === "severity" && isScoreFindingSeverity(value))
		rule.severity = value;
	else if (normalizedKey === "reason") rule.reason = value;
	else if (normalizedKey === "expiresat" || normalizedKey === "expires")
		rule.expiresAt = value;
}

function applyFindingIgnorePolicy(
	findings: ScoreFinding[],
	policy: FindingIgnorePolicy,
) {
	const activeRules = policy.rules.filter(isActiveIgnoreRule);
	const ignored: ScoreFinding[] = [];
	const kept = findings.filter((finding) => {
		const matched = activeRules.some((rule) =>
			ignoreRuleMatches(rule, finding),
		);
		if (matched) ignored.push(finding);
		return !matched;
	});
	return { findings: kept, ignored };
}

function isActiveIgnoreRule(rule: FindingIgnoreRule) {
	if (!rule.expiresAt) return true;
	const expiresAt = Date.parse(rule.expiresAt);
	return Number.isNaN(expiresAt) || expiresAt >= Date.now();
}

function ignoreRuleMatches(rule: FindingIgnoreRule, finding: ScoreFinding) {
	if (rule.source && rule.source !== finding.source) return false;
	if (rule.category && rule.category !== finding.category) return false;
	if (rule.severity && rule.severity !== finding.severity) return false;
	if (rule.ruleId && rule.ruleId !== finding.ruleId) return false;
	if (rule.id && rule.id !== finding.ruleId) return false;
	if (rule.path && !pathMatches(rule.path, finding.file)) return false;
	return Boolean(
		rule.source ||
			rule.category ||
			rule.severity ||
			rule.ruleId ||
			rule.id ||
			rule.path,
	);
}

function pathMatches(pattern: string, path: string | undefined) {
	if (!path) return false;
	if (pattern === path) return true;
	if (pattern.endsWith("/**")) return path.startsWith(pattern.slice(0, -3));
	if (pattern.startsWith("**/")) return path.endsWith(pattern.slice(3));
	return path.includes(pattern);
}

function isScoreFindingSource(value: string): value is ScoreFinding["source"] {
	return ["heuristic", "semgrep", "sarif", "gitleaks", "osv"].includes(value);
}

function isScoreFindingCategory(
	value: string,
): value is ScoreFinding["category"] {
	return [
		"auth",
		"payment",
		"secret",
		"dependency",
		"upload",
		"config",
		"data-access",
	].includes(value);
}

function isScoreFindingSeverity(
	value: string,
): value is ScoreFinding["severity"] {
	return ["critical", "high", "medium", "low", "info"].includes(value);
}

export function getScoreFailureTransition(
	attemptCount: number,
	maxAttempts = DEFAULT_SCORE_MAX_ATTEMPTS,
	now = new Date().toISOString(),
): ScoreFailureTransition {
	const exhausted = attemptCount >= Math.max(1, Math.floor(maxAttempts));
	return {
		status: exhausted ? "failed" : "queued",
		startedAt: null,
		completedAt: exhausted ? now : null,
	};
}

export async function runOptionalExternalScans(
	files: ScoreInputFile[],
	env: Record<string, string | undefined>,
	options: ProcessOptions,
): Promise<ScoreAnalysisOptions> {
	const [semgrep, gitleaks, osv] = await Promise.all([
		runOptionalSemgrepScan(files, env, options),
		runOptionalGitleaksScan(files, env, options),
		runOptionalOsvScan(files, env, options),
	]);
	const externalFindings = [
		...semgrep.findings,
		...gitleaks.findings,
		...osv.findings,
	];
	const externalScanCoverage = {
		...(semgrep.coverage ? { semgrep: semgrep.coverage } : {}),
		...(gitleaks.coverage ? { gitleaks: gitleaks.coverage } : {}),
		...(osv.coverage ? { osv: osv.coverage } : {}),
	};
	const externalScannerResults = {
		...(semgrep.coverage ? { semgrep: buildStoredScannerResult(semgrep) } : {}),
		...(gitleaks.coverage
			? { gitleaks: buildStoredScannerResult(gitleaks) }
			: {}),
		...(osv.coverage ? { osv: buildStoredScannerResult(osv) } : {}),
	};
	if (
		externalFindings.length === 0 &&
		Object.keys(externalScanCoverage).length === 0
	)
		return {};
	return { externalFindings, externalScanCoverage, externalScannerResults };
}

function buildStoredScannerResult(outcome: ExternalScanOutcome) {
	return {
		...outcome.coverage,
		findingCount: outcome.findings.length,
		severityCounts: countFindingsBy(outcome.findings, "severity"),
		categoryCounts: countFindingsBy(outcome.findings, "category"),
		findings: outcome.findings.map((finding) => ({
			source: finding.source,
			ruleId: finding.ruleId,
			category: finding.category,
			severity: finding.severity,
			title: finding.title,
			evidence: finding.evidence,
			file: finding.file,
			confidence: finding.confidence,
			cwe: finding.cwe,
			owasp: finding.owasp,
			remediationHint: finding.remediationHint,
		})),
	};
}

function countFindingsBy(
	findings: ScoreFinding[],
	key: "severity" | "category",
) {
	return findings.reduce<Record<string, number>>((counts, finding) => {
		counts[finding[key]] = (counts[finding[key]] ?? 0) + 1;
		return counts;
	}, {});
}

async function runOptionalSemgrepScan(
	files: ScoreInputFile[],
	env: Record<string, string | undefined>,
	options: ProcessOptions,
): Promise<{
	findings: ScoreFinding[];
	coverage?: Record<string, unknown>;
}> {
	const semgrepOptions = buildSemgrepScanOptions(env, options.semgrep);
	if (!semgrepOptions.enabled) {
		return {
			findings: [],
			coverage: { enabled: false },
		};
	}

	try {
		const result = await runSemgrepScan(files, semgrepOptions);
		return {
			findings: result.findings,
			coverage: {
				enabled: true,
				status: "completed",
				configs: semgrepOptions.configs,
				findings: result.findings.length,
				...result.coverage,
			},
		};
	} catch (error) {
		const message =
			error instanceof Error ? error.message : "Unknown Semgrep error";
		options.logger?.error(`Optional Semgrep scan failed: ${message}`);
		return {
			findings: [],
			coverage: {
				enabled: true,
				status: "failed",
				configs: semgrepOptions.configs,
				proMode: semgrepOptions.proMode,
				secretsEnabled: semgrepOptions.secretsEnabled,
				extraArgs: semgrepOptions.extraArgs,
				error: message.slice(0, 300),
			},
		};
	}
}

async function runOptionalGitleaksScan(
	files: ScoreInputFile[],
	env: Record<string, string | undefined>,
	options: ProcessOptions,
): Promise<{
	findings: ScoreFinding[];
	coverage?: Record<string, unknown>;
}> {
	const gitleaksOptions = buildGitleaksScanOptions(env, options.gitleaks);
	if (!gitleaksOptions.enabled) {
		return { findings: [], coverage: { enabled: false } };
	}

	try {
		const result = await runGitleaksScan(files, gitleaksOptions);
		return {
			findings: result.findings,
			coverage: {
				enabled: true,
				status: "completed",
				findings: result.findings.length,
				...result.coverage,
			},
		};
	} catch (error) {
		const message =
			error instanceof Error ? error.message : "Unknown Gitleaks error";
		options.logger?.error(`Optional Gitleaks scan failed: ${message}`);
		return {
			findings: [],
			coverage: {
				enabled: true,
				status: "failed",
				extraArgs: gitleaksOptions.extraArgs,
				error: message.slice(0, 300),
			},
		};
	}
}

async function runOptionalOsvScan(
	files: ScoreInputFile[],
	env: Record<string, string | undefined>,
	options: ProcessOptions,
): Promise<{
	findings: ScoreFinding[];
	coverage?: Record<string, unknown>;
}> {
	const osvOptions = buildOsvScanOptions(env, options.osv);
	if (!osvOptions.enabled) {
		return { findings: [], coverage: { enabled: false } };
	}

	try {
		const result = await runOsvScan(files, osvOptions);
		return {
			findings: result.findings,
			coverage: {
				enabled: true,
				status: "completed",
				findings: result.findings.length,
				...result.coverage,
			},
		};
	} catch (error) {
		const message =
			error instanceof Error ? error.message : "Unknown OSV error";
		options.logger?.error(`Optional OSV scan failed: ${message}`);
		return {
			findings: [],
			coverage: {
				enabled: true,
				status: "failed",
				extraArgs: osvOptions.extraArgs,
				error: message.slice(0, 300),
			},
		};
	}
}

function buildSemgrepScanOptions(
	env: Record<string, string | undefined>,
	overrides: ProcessOptions["semgrep"],
): SemgrepScanOptions {
	const overrideObject =
		overrides && typeof overrides === "object" ? overrides : {};
	return {
		enabled:
			overrides !== false &&
			(overrideObject.enabled ?? env.SEMGREP_ENABLED === "true"),
		command: overrideObject.command ?? env.SEMGREP_COMMAND ?? "semgrep",
		configs: overrideObject.configs ??
			parseList(env.SEMGREP_CONFIGS) ?? [
				"p/security-audit",
				"p/owasp-top-ten",
				"p/secrets",
				"p/python",
				"p/rust",
				"p/javascript",
				"p/typescript",
			],
		extraArgs:
			overrideObject.extraArgs ?? parseList(env.SEMGREP_EXTRA_ARGS) ?? [],
		proMode: normalizeSemgrepProMode(
			overrideObject.proMode ?? env.SEMGREP_PRO_MODE,
		),
		secretsEnabled:
			overrideObject.secretsEnabled ?? env.SEMGREP_SECRETS_ENABLED === "true",
		timeoutMs: positiveIntegerOrDefault(
			overrideObject.timeoutMs ?? Number(env.SEMGREP_TIMEOUT_MS),
			60_000,
			1_000,
		),
		maxFindings: positiveIntegerOrDefault(
			overrideObject.maxFindings ?? Number(env.SEMGREP_MAX_FINDINGS),
			100,
			1,
		),
	};
}

function buildGitleaksScanOptions(
	env: Record<string, string | undefined>,
	overrides: ProcessOptions["gitleaks"],
): GitleaksScanOptions {
	const overrideObject =
		overrides && typeof overrides === "object" ? overrides : {};
	return {
		enabled:
			overrides !== false &&
			(overrideObject.enabled ?? env.GITLEAKS_ENABLED === "true"),
		command: overrideObject.command ?? env.GITLEAKS_COMMAND ?? "gitleaks",
		extraArgs:
			overrideObject.extraArgs ?? parseList(env.GITLEAKS_EXTRA_ARGS) ?? [],
		timeoutMs: positiveIntegerOrDefault(
			overrideObject.timeoutMs ?? Number(env.GITLEAKS_TIMEOUT_MS),
			60_000,
			1_000,
		),
		maxFindings: positiveIntegerOrDefault(
			overrideObject.maxFindings ?? Number(env.GITLEAKS_MAX_FINDINGS),
			100,
			1,
		),
	};
}

function buildOsvScanOptions(
	env: Record<string, string | undefined>,
	overrides: ProcessOptions["osv"],
): OsvScanOptions {
	const overrideObject =
		overrides && typeof overrides === "object" ? overrides : {};
	return {
		enabled:
			overrides !== false &&
			(overrideObject.enabled ?? env.OSV_ENABLED === "true"),
		command: overrideObject.command ?? env.OSV_COMMAND ?? "osv-scanner",
		extraArgs: overrideObject.extraArgs ?? parseList(env.OSV_EXTRA_ARGS) ?? [],
		timeoutMs: positiveIntegerOrDefault(
			overrideObject.timeoutMs ?? Number(env.OSV_TIMEOUT_MS),
			120_000,
			1_000,
		),
		maxFindings: positiveIntegerOrDefault(
			overrideObject.maxFindings ?? Number(env.OSV_MAX_FINDINGS),
			100,
			1,
		),
	};
}

function parseList(value: string | undefined) {
	const items = value
		?.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
	return items && items.length > 0 ? items : undefined;
}

function normalizeSemgrepProMode(
	value: string | undefined,
): SemgrepScanOptions["proMode"] {
	const normalized = value?.trim().toLowerCase();
	if (normalized === "true" || normalized === "pro") return "pro";
	if (normalized === "intrafile" || normalized === "pro-intrafile")
		return "intrafile";
	if (normalized === "path-sensitive" || normalized === "pro-path-sensitive")
		return "path-sensitive";
	return "off";
}

function buildSemgrepEngineArgs(options: SemgrepScanOptions) {
	if (options.proMode === "path-sensitive") return ["--pro-path-sensitive"];
	if (options.proMode === "intrafile") return ["--pro-intrafile"];
	if (options.proMode === "pro") return ["--pro"];
	return [];
}

function buildSemgrepCoverage(
	output: Record<string, unknown>,
	options: SemgrepScanOptions,
) {
	const paths = isRecord(output.paths) ? output.paths : {};
	const scanned = Array.isArray(paths.scanned) ? paths.scanned : [];
	const skipped = Array.isArray(paths.skipped) ? paths.skipped : [];
	const errors = Array.isArray(output.errors) ? output.errors : [];
	const skippedRules = Array.isArray(output.skipped_rules)
		? output.skipped_rules
		: [];
	const time = isRecord(output.time) ? output.time : {};
	const profilingTimes = isRecord(time.profiling_times)
		? time.profiling_times
		: {};
	return {
		version: stringValue(output.version),
		engineRequested: stringValue(output.engine_requested),
		engineUsed: stringValue(output.engine_used),
		proMode: options.proMode,
		secretsEnabled: options.secretsEnabled,
		extraArgs: options.extraArgs,
		scannedFiles: scanned.length,
		skippedFiles: skipped.length,
		skippedRules: skippedRules.length,
		errors: errors.length,
		errorSummaries: errors.slice(0, 5).map(summarizeSemgrepError),
		totalTimeSeconds: numberValue(profilingTimes.total_time),
	};
}

function summarizeSemgrepError(error: unknown) {
	if (!isRecord(error)) return String(error).slice(0, 200);
	return (
		stringValue(error.message) ??
		stringValue(error.type) ??
		JSON.stringify(error).slice(0, 200)
	);
}

async function runSemgrepScan(
	files: ScoreInputFile[],
	options: SemgrepScanOptions,
) {
	const workspace = await mkdtemp(join(tmpdir(), "oh-my-audit-semgrep-"));
	try {
		await writeAnalysisFiles(workspace, files);
		const args = [
			"scan",
			"--json",
			"--quiet",
			"--disable-version-check",
			"--metrics=off",
			...buildSemgrepEngineArgs(options),
			...(options.secretsEnabled ? ["--secrets"] : []),
			...options.configs.flatMap((config) => ["--config", config]),
			...options.extraArgs,
			".",
		];
		const output = await execSemgrepJson(
			options.command,
			args,
			workspace,
			options,
		);
		return {
			findings: normalizeSemgrepJsonFindings(output, options.maxFindings),
			coverage: buildSemgrepCoverage(output, options),
		};
	} finally {
		await rm(workspace, { recursive: true, force: true });
	}
}

async function runGitleaksScan(
	files: ScoreInputFile[],
	options: GitleaksScanOptions,
) {
	const workspace = await mkdtemp(join(tmpdir(), "oh-my-audit-gitleaks-"));
	try {
		await writeAnalysisFiles(workspace, files);
		const reportPath = join(workspace, "gitleaks-report.json");
		const args = [
			"detect",
			"--source",
			".",
			"--no-git",
			"--redact",
			"--exit-code",
			"0",
			"--report-format",
			"json",
			"--report-path",
			reportPath,
			...options.extraArgs,
		];
		await execFileAsync(options.command, args, {
			cwd: workspace,
			timeout: options.timeoutMs,
			maxBuffer: 10 * 1024 * 1024,
			env: buildScannerEnv(process.env),
		});
		const output = parseJsonArray(
			await readFile(reportPath, "utf8"),
			"Gitleaks JSON output",
		);
		return {
			findings: normalizeGitleaksJsonFindings(output, options.maxFindings),
			coverage: {
				extraArgs: options.extraArgs,
				scannedFiles: files.length,
			},
		};
	} finally {
		await rm(workspace, { recursive: true, force: true });
	}
}

async function runOsvScan(files: ScoreInputFile[], options: OsvScanOptions) {
	const workspace = await mkdtemp(join(tmpdir(), "oh-my-audit-osv-"));
	try {
		await writeAnalysisFiles(workspace, files);
		const args = [
			"scan",
			"--recursive",
			"--format",
			"json",
			...options.extraArgs,
			".",
		];
		const output = await execOsvJson(options.command, args, workspace, options);
		return {
			findings: normalizeOsvJsonFindings(
				output,
				options.maxFindings,
				workspace,
			),
			coverage: buildOsvCoverage(output, options, workspace),
		};
	} finally {
		await rm(workspace, { recursive: true, force: true });
	}
}

async function writeAnalysisFiles(root: string, files: ScoreInputFile[]) {
	for (const file of files) {
		const target = join(root, file.path);
		if (!target.startsWith(`${root}/`))
			throw new Error("Unsafe analysis path.");
		await mkdir(dirname(target), { recursive: true });
		await writeFile(target, file.content, "utf8");
	}
}

async function execSemgrepJson(
	command: string,
	args: string[],
	cwd: string,
	options: SemgrepScanOptions,
) {
	try {
		const { stdout } = await execFileAsync(command, args, {
			cwd,
			timeout: options.timeoutMs,
			maxBuffer: 10 * 1024 * 1024,
			env: buildScannerEnv(process.env, { SEMGREP_SEND_METRICS: "off" }),
		});
		return parseJsonObject(stdout, "Semgrep JSON output");
	} catch (error) {
		const maybeStdout = (error as { stdout?: string | Buffer }).stdout;
		if (maybeStdout) return parseJsonObject(maybeStdout, "Semgrep JSON output");
		throw error;
	}
}

async function execOsvJson(
	command: string,
	args: string[],
	cwd: string,
	options: OsvScanOptions,
) {
	try {
		const { stdout } = await execFileAsync(command, args, {
			cwd,
			timeout: options.timeoutMs,
			maxBuffer: 20 * 1024 * 1024,
			env: buildScannerEnv(process.env),
		});
		return parseJsonObject(stdout, "OSV JSON output");
	} catch (error) {
		const maybeStdout = (error as { stdout?: string | Buffer }).stdout;
		if (maybeStdout) return parseJsonObject(maybeStdout, "OSV JSON output");
		throw error;
	}
}

function parseJsonObject(value: string | Buffer, label: string) {
	try {
		return JSON.parse(String(value)) as Record<string, unknown>;
	} catch {
		throw new Error(`${label} was not valid JSON.`);
	}
}

function parseJsonArray(value: string | Buffer, label: string) {
	try {
		const parsed = JSON.parse(String(value)) as unknown;
		if (Array.isArray(parsed)) return parsed;
		throw new Error("not an array");
	} catch {
		throw new Error(`${label} was not a valid JSON array.`);
	}
}

export function normalizeSemgrepJsonFindings(
	output: Record<string, unknown>,
	maxFindings = 100,
): ScoreFinding[] {
	const results = Array.isArray(output.results) ? output.results : [];
	return results
		.slice(0, maxFindings)
		.map((result) =>
			normalizeSemgrepJsonResult(result as Record<string, unknown>),
		);
}

function normalizeSemgrepJsonResult(
	result: Record<string, unknown>,
): ScoreFinding {
	const extra = isRecord(result.extra) ? result.extra : {};
	const metadata = isRecord(extra.metadata) ? extra.metadata : {};
	const ruleId = stringValue(result.check_id) ?? "semgrep.unknown";
	const path = stringValue(result.path);
	const start = isRecord(result.start) ? result.start : {};
	const line = numberValue(start.line);
	return {
		source: "semgrep",
		ruleId,
		category: inferFindingCategory(
			ruleId,
			metadata,
			stringValue(extra.message),
		),
		severity: mapExternalSeverity(
			stringValue(extra.severity),
			numberValue(metadata["security-severity"]),
		),
		title: stringValue(extra.message) ?? ruleId,
		evidence: line ? `${path ?? "unknown file"}:${line}` : (path ?? ruleId),
		file: path,
		confidence: mapExternalConfidence(metadata.confidence),
		cwe: extractSecurityTags(metadata.cwe, metadata.cwe_id, metadata.cwe_ids),
		owasp: extractSecurityTags(
			metadata.owasp,
			metadata.owasp2021,
			metadata.owasp_top_10,
		),
		remediationHint:
			stringValue(metadata.fix) ??
			stringValue(metadata.remediation) ??
			"Review the Semgrep finding and apply the rule-specific remediation guidance.",
	};
}

function normalizeScannerPath(path: string | undefined, root?: string) {
	if (!path) return undefined;
	const rootPath = root;
	const normalizedRoot = rootPath?.replace(/\\/g, "/").replace(/\/$/, "");
	const normalizedPath = path.replace(/\\/g, "/");
	if (
		rootPath &&
		normalizedRoot &&
		normalizedPath.startsWith(`${normalizedRoot}/`)
	) {
		const relativePath = relative(rootPath, path).replace(/\\/g, "/");
		return relativePath && !relativePath.startsWith("..") ? relativePath : path;
	}
	return normalizedPath.replace(/^\.\//, "");
}

export function normalizeGitleaksJsonFindings(
	results: unknown[],
	maxFindings = 100,
): ScoreFinding[] {
	return results
		.slice(0, maxFindings)
		.filter(isRecord)
		.map((result) => {
			const ruleId = stringValue(result.RuleID) ?? "gitleaks.unknown";
			const file = stringValue(result.File);
			const line = numberValue(result.StartLine);
			const description = stringValue(result.Description) ?? ruleId;
			return {
				source: "gitleaks",
				ruleId,
				category: "secret",
				severity: inferGitleaksSeverity(ruleId),
				title: `Secret detected: ${description}`,
				evidence: line ? `${file ?? "unknown file"}:${line}` : (file ?? ruleId),
				file,
				confidence: "high",
				cwe: ["CWE-798"],
				owasp: ["A05:2021-Security Misconfiguration"],
				remediationHint:
					"Remove the secret from source, rotate it if it was real, and move it to a secret manager or server-only environment variable.",
			} satisfies ScoreFinding;
		});
}

export function normalizeOsvJsonFindings(
	output: Record<string, unknown>,
	maxFindings = 100,
	root?: string,
): ScoreFinding[] {
	const findings: ScoreFinding[] = [];
	const seen = new Set<string>();
	const results = Array.isArray(output.results) ? output.results : [];
	for (const result of results) {
		if (!isRecord(result)) continue;
		const source = isRecord(result.source) ? result.source : {};
		const sourcePath = normalizeScannerPath(stringValue(source.path), root);
		const dependencyScope = inferDependencyScope(sourcePath);
		const packages = Array.isArray(result.packages) ? result.packages : [];
		for (const packageResult of packages) {
			if (!isRecord(packageResult)) continue;
			const packageInfo = isRecord(packageResult.package)
				? packageResult.package
				: {};
			const packageName = stringValue(packageInfo.name) ?? "unknown package";
			const ecosystem = stringValue(packageInfo.ecosystem);
			const version = stringValue(packageInfo.version);
			const vulnerabilities = Array.isArray(packageResult.vulnerabilities)
				? packageResult.vulnerabilities
				: [];
			for (const vulnerability of vulnerabilities) {
				if (!isRecord(vulnerability)) continue;
				if (findings.length >= maxFindings) return findings;
				const id = stringValue(vulnerability.id) ?? "osv.unknown";
				const dedupeId = canonicalOsvVulnerabilityId(vulnerability, id);
				const dedupeKey = [dedupeId, ecosystem, packageName, sourcePath].join(
					"|",
				);
				if (seen.has(dedupeKey)) continue;
				seen.add(dedupeKey);
				const summary = stringValue(vulnerability.summary) ?? id;
				const databaseSpecific = isRecord(vulnerability.database_specific)
					? vulnerability.database_specific
					: {};
				findings.push({
					source: "osv",
					ruleId: id,
					category: "dependency",
					severity: mapOsvSeverity(vulnerability, databaseSpecific),
					title: `Dependency vulnerability: ${summary}`,
					evidence:
						[
							sourcePath,
							[ecosystem, packageName, version].filter(Boolean).join(":"),
							`scope:${dependencyScope}`,
						]
							.filter(Boolean)
							.join(" - ") || id,
					file: sourcePath,
					confidence: "high",
					cwe: extractSecurityTags(
						databaseSpecific.cwe_ids,
						vulnerability.cwe_ids,
					),
					remediationHint:
						"Upgrade the affected dependency to a fixed version, replace it, or document a justified ignore with compensating controls.",
				});
			}
		}
	}
	return findings;
}

function canonicalOsvVulnerabilityId(
	vulnerability: Record<string, unknown>,
	fallback: string,
) {
	const aliases = Array.isArray(vulnerability.aliases)
		? vulnerability.aliases.map(stringValue).filter(Boolean)
		: [];
	const ids = [fallback, ...aliases].filter(Boolean).sort();
	return ids[0] ?? fallback;
}

function inferDependencyScope(path: string | undefined) {
	const fileName = path?.toLowerCase().split("/").pop();
	if (!fileName) return "unknown";
	if (
		[
			"package.json",
			"go.mod",
			"cargo.toml",
			"requirements.txt",
			"pyproject.toml",
			"pom.xml",
		].includes(fileName)
	)
		return "direct-manifest";
	if (
		[
			"package-lock.json",
			"pnpm-lock.yaml",
			"yarn.lock",
			"bun.lockb",
			"go.sum",
			"cargo.lock",
			"poetry.lock",
			"uv.lock",
		].includes(fileName)
	)
		return "lockfile";
	return "unknown";
}

function buildOsvCoverage(
	output: Record<string, unknown>,
	options: OsvScanOptions,
	root?: string,
) {
	const findings = normalizeOsvJsonFindings(output, options.maxFindings, root);
	const results = Array.isArray(output.results) ? output.results : [];
	const packagesScanned = results.reduce((sum, result) => {
		if (!isRecord(result) || !Array.isArray(result.packages)) return sum;
		return sum + result.packages.length;
	}, 0);
	return {
		extraArgs: options.extraArgs,
		results: results.length,
		packagesScanned,
		vulnerabilities: findings.length,
	};
}

function inferGitleaksSeverity(ruleId: string): ScoreFinding["severity"] {
	const lower = ruleId.toLowerCase();
	if (/private-key|ssh|aws|github|gitlab|slack|stripe|openai/.test(lower))
		return "critical";
	return "high";
}

function mapOsvSeverity(
	vulnerability: Record<string, unknown>,
	databaseSpecific: Record<string, unknown>,
): ScoreFinding["severity"] {
	const severity = stringValue(databaseSpecific.severity)?.toLowerCase();
	if (severity === "critical") return "critical";
	if (severity === "high") return "high";
	if (severity === "medium" || severity === "moderate") return "medium";
	if (severity === "low") return "low";
	const severities = Array.isArray(vulnerability.severity)
		? vulnerability.severity
		: [];
	const scoreText = severities
		.filter(isRecord)
		.map((entry) => stringValue(entry.score))
		.find(Boolean);
	const score = scoreText ? parseCvssBaseScore(scoreText) : undefined;
	if (score !== undefined) {
		if (score >= 9) return "critical";
		if (score >= 7) return "high";
		if (score >= 4) return "medium";
		return "low";
	}
	return "medium";
}

function parseCvssBaseScore(vector: string) {
	const match = /(?:^|\b)(\d+(?:\.\d+)?)(?:\b|$)/.exec(vector);
	return match ? Number(match[1]) : undefined;
}

export function normalizeSarifFindings(
	log: Record<string, unknown>,
	maxFindings = 100,
): ScoreFinding[] {
	const runs = Array.isArray(log.runs) ? log.runs : [];
	const findings: ScoreFinding[] = [];
	for (const run of runs) {
		const ruleMetadata = getSarifRuleMetadata(run as Record<string, unknown>);
		const results =
			isRecord(run) && Array.isArray(run.results) ? run.results : [];
		for (const result of results) {
			if (findings.length >= maxFindings) return findings;
			findings.push(
				normalizeSarifResult(result as Record<string, unknown>, ruleMetadata),
			);
		}
	}
	return findings;
}

function normalizeSarifResult(
	result: Record<string, unknown>,
	ruleMetadata: Map<string, Record<string, unknown>>,
): ScoreFinding {
	const ruleId = stringValue(result.ruleId) ?? "sarif.unknown";
	const metadata = ruleMetadata.get(ruleId) ?? {};
	const message = isRecord(result.message)
		? (stringValue(result.message.text) ?? stringValue(result.message.markdown))
		: undefined;
	const location = getSarifPrimaryLocation(result);
	return {
		source: "sarif",
		ruleId,
		category: inferFindingCategory(ruleId, metadata, message),
		severity: mapExternalSeverity(
			stringValue(result.level),
			numberValue(metadata["security-severity"]),
		),
		title: message ?? stringValue(metadata.name) ?? ruleId,
		evidence: location.line
			? `${location.path ?? "unknown file"}:${location.line}`
			: (location.path ?? ruleId),
		file: location.path,
		confidence: mapExternalConfidence(metadata.confidence),
		cwe: extractSecurityTags(metadata.cwe, metadata.tags),
		owasp: extractSecurityTags(metadata.owasp, metadata.tags),
		remediationHint:
			stringValue(metadata.help) ??
			stringValue(metadata["help.text"]) ??
			"Review the SARIF finding and apply the tool-specific remediation guidance.",
	};
}

function getSarifRuleMetadata(run: Record<string, unknown>) {
	const rules =
		isRecord(run.tool) &&
		isRecord(run.tool.driver) &&
		Array.isArray(run.tool.driver.rules)
			? run.tool.driver.rules
			: [];
	const metadata = new Map<string, Record<string, unknown>>();
	for (const rule of rules) {
		if (!isRecord(rule)) continue;
		const id = stringValue(rule.id);
		if (!id) continue;
		metadata.set(id, {
			...rule,
			...(isRecord(rule.properties) ? rule.properties : {}),
		});
	}
	return metadata;
}

function getSarifPrimaryLocation(result: Record<string, unknown>) {
	const locations = Array.isArray(result.locations) ? result.locations : [];
	const location = isRecord(locations[0]) ? locations[0] : {};
	const physicalLocation = isRecord(location.physicalLocation)
		? location.physicalLocation
		: {};
	const artifactLocation = isRecord(physicalLocation.artifactLocation)
		? physicalLocation.artifactLocation
		: {};
	const region = isRecord(physicalLocation.region)
		? physicalLocation.region
		: {};
	return {
		path: stringValue(artifactLocation.uri),
		line: numberValue(region.startLine),
	};
}

function inferFindingCategory(
	ruleId: string,
	metadata: Record<string, unknown>,
	message = "",
): ScoreFinding["category"] {
	const haystack = [
		ruleId,
		message,
		...extractSecurityTags(
			metadata.category,
			metadata.categories,
			metadata.tags,
		),
	]
		.join(" ")
		.toLowerCase();
	if (/secret|credential|token|private.key|api.key/.test(haystack))
		return "secret";
	if (/webhook|payment|stripe|checkout|invoice|order/.test(haystack))
		return "payment";
	if (/upload|file|path.traversal|archive|zip/.test(haystack)) return "upload";
	if (/auth|access.control|permission|role|cookie|session|jwt/.test(haystack))
		return "auth";
	if (/dependency|vulnerable|cve|supply.chain|package/.test(haystack))
		return "dependency";
	if (/sql|database|tenant|idor|injection|xss|csrf/.test(haystack))
		return "data-access";
	return "config";
}

function mapExternalSeverity(
	severity: string | undefined,
	securitySeverity: number | undefined,
): ScoreFinding["severity"] {
	if (securitySeverity !== undefined) {
		if (securitySeverity >= 9) return "critical";
		if (securitySeverity >= 7) return "high";
		if (securitySeverity >= 4) return "medium";
		return "low";
	}
	const normalized = severity?.toLowerCase();
	if (normalized === "critical") return "critical";
	if (normalized === "error" || normalized === "high") return "high";
	if (normalized === "warning" || normalized === "medium") return "medium";
	if (normalized === "note" || normalized === "info" || normalized === "low")
		return "low";
	return "medium";
}

function mapExternalConfidence(value: unknown): ScoreFinding["confidence"] {
	const confidence = stringValue(value)?.toLowerCase();
	if (confidence === "high" || confidence === "medium" || confidence === "low")
		return confidence;
	return "medium";
}

function extractSecurityTags(...values: unknown[]) {
	return values
		.flatMap((value) => {
			if (Array.isArray(value)) return value.map(String);
			if (typeof value === "string") return [value];
			return [];
		})
		.filter(Boolean);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

function stringValue(value: unknown) {
	return typeof value === "string" ? value : undefined;
}

function numberValue(value: unknown) {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "string") {
		const parsed = Number(value);
		if (Number.isFinite(parsed)) return parsed;
	}
	return undefined;
}


type ZipEntry = {
	path: string;
	compressionMethod: number;
	compressedSize: number;
	uncompressedSize: number;
	localHeaderOffset: number;
	directory: boolean;
};

function readZipEntries(zip: Buffer): ZipEntry[] {
	const eocdOffset = findEndOfCentralDirectory(zip);
	const centralDirectorySize = zip.readUInt32LE(eocdOffset + 12);
	const centralDirectoryOffset = zip.readUInt32LE(eocdOffset + 16);
	const entries: ZipEntry[] = [];
	let cursor = centralDirectoryOffset;
	const end = centralDirectoryOffset + centralDirectorySize;

	while (cursor < end) {
		if (zip.readUInt32LE(cursor) !== 0x02014b50)
			throw new Error("Invalid zip central directory.");
		const flags = zip.readUInt16LE(cursor + 8);
		const compressionMethod = zip.readUInt16LE(cursor + 10);
		const compressedSize = zip.readUInt32LE(cursor + 20);
		const uncompressedSize = zip.readUInt32LE(cursor + 24);
		const nameLength = zip.readUInt16LE(cursor + 28);
		const extraLength = zip.readUInt16LE(cursor + 30);
		const commentLength = zip.readUInt16LE(cursor + 32);
		const localHeaderOffset = zip.readUInt32LE(cursor + 42);
		const path = zip
			.subarray(cursor + 46, cursor + 46 + nameLength)
			.toString(flags & 0x800 ? "utf8" : "utf8");

		entries.push({
			path,
			compressionMethod,
			compressedSize,
			uncompressedSize,
			localHeaderOffset,
			directory: path.endsWith("/"),
		});
		cursor += 46 + nameLength + extraLength + commentLength;
	}

	return entries;
}

function readZipEntryData(zip: Buffer, entry: ZipEntry, maxBytes: number) {
	const offset = entry.localHeaderOffset;
	if (zip.readUInt32LE(offset) !== 0x04034b50)
		throw new Error("Invalid zip local file header.");
	const nameLength = zip.readUInt16LE(offset + 26);
	const extraLength = zip.readUInt16LE(offset + 28);
	const dataOffset = offset + 30 + nameLength + extraLength;
	const compressed = zip.subarray(
		dataOffset,
		dataOffset + entry.compressedSize,
	);

	// Never trust the declared uncompressed size from the central directory: a
	// decompression bomb can claim a tiny size while inflating to gigabytes.
	// Cap the actual output so a malicious entry throws instead of exhausting
	// memory, and verify the stored (uncompressed) path against the same limit.
	if (entry.compressionMethod === 0) {
		if (compressed.length > maxBytes)
			throw new Error("Zip entry exceeds the per-file size limit.");
		return compressed;
	}
	if (entry.compressionMethod === 8)
		return inflateRawSync(compressed, { maxOutputLength: maxBytes });
	throw new Error(
		`Unsupported zip compression method: ${entry.compressionMethod}`,
	);
}

function findEndOfCentralDirectory(zip: Buffer) {
	const minOffset = Math.max(0, zip.length - 65_557);
	for (let offset = zip.length - 22; offset >= minOffset; offset -= 1) {
		if (zip.readUInt32LE(offset) === 0x06054b50) return offset;
	}
	throw new Error("Invalid zip file.");
}

function normalizeSafeZipPath(path: string) {
	const normalized = path.replace(/\\/g, "/").replace(/^\.\//, "");
	if (
		!normalized ||
		normalized.includes("\0") ||
		normalized.startsWith("/") ||
		/^[a-z]:/i.test(normalized)
	)
		return null;
	const segments = normalized.split("/");
	if (
		segments.some((segment) => !segment || segment === "." || segment === "..")
	)
		return null;
	return segments.join("/");
}

function shouldExcludePath(path: string) {
	return path.split("/").some((segment) => EXCLUDED_SEGMENTS.has(segment));
}

function shouldReadTextFile(path: string) {
	const lowerPath = path.toLowerCase();
	const fileName = lowerPath.split("/").pop() ?? lowerPath;
	if (IMPORTANT_FILE_NAMES.has(fileName)) return true;
	const dotIndex = fileName.lastIndexOf(".");
	return dotIndex >= 0 && TEXT_EXTENSIONS.has(fileName.slice(dotIndex));
}

function isLikelyText(data: Buffer) {
	if (data.includes(0)) return false;
	return true;
}

function isEnvFile(path: string) {
	const fileName = path.split("/").pop() ?? path;
	return fileName === ".env" || fileName.startsWith(".env.");
}

type ScoreFindingDraft = Omit<ScoreFinding, "source" | "ruleId"> & {
	source?: ScoreFinding["source"];
};

type SecretDetector = {
	title: string;
	pattern: RegExp;
	severity: ScoreFinding["severity"];
	confidence: ScoreFinding["confidence"];
	evidence: string;
	cwe?: string[];
	owasp?: string[];
	remediationHint: string;
};

const SECRET_DETECTORS: SecretDetector[] = [
	{
		title: "Private key block found in source",
		pattern:
			/-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/i,
		severity: "critical",
		confidence: "high",
		evidence: "A private key PEM block was detected in a source file.",
		cwe: ["CWE-798"],
		owasp: ["A02:2021-Cryptographic Failures"],
		remediationHint:
			"Remove the private key from source, rotate it, and load it from a managed secret store at runtime.",
	},
	{
		title: "AWS access key ID found in source",
		pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
		severity: "high",
		confidence: "high",
		evidence: "An AWS access key identifier pattern was detected.",
		cwe: ["CWE-798"],
		owasp: ["A05:2021-Security Misconfiguration"],
		remediationHint:
			"Revoke and rotate the AWS key, then use IAM roles or environment-backed secret injection.",
	},
	{
		title: "GitHub token found in source",
		pattern:
			/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
		severity: "high",
		confidence: "high",
		evidence: "A GitHub personal or fine-grained token pattern was detected.",
		cwe: ["CWE-798"],
		owasp: ["A07:2021-Identification and Authentication Failures"],
		remediationHint:
			"Revoke the token in GitHub, remove it from history, and store future tokens outside the repository.",
	},
	{
		title: "Payment provider secret found in source",
		pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b|\bwhsec_[A-Za-z0-9]{16,}\b/g,
		severity: "critical",
		confidence: "high",
		evidence: "A live payment secret or webhook secret pattern was detected.",
		cwe: ["CWE-798"],
		owasp: ["A04:2021-Insecure Design", "A05:2021-Security Misconfiguration"],
		remediationHint:
			"Rotate the payment secret immediately and move it to server-only environment configuration.",
	},
	{
		title: "OpenAI-style API key found in source",
		pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
		severity: "high",
		confidence: "high",
		evidence: "An OpenAI-style API key pattern was detected.",
		cwe: ["CWE-798"],
		owasp: ["A05:2021-Security Misconfiguration"],
		remediationHint:
			"Rotate the API key and make sure AI provider keys are only available to trusted server code.",
	},
	{
		title: "JWT-like bearer token found in source",
		pattern:
			/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
		severity: "medium",
		confidence: "medium",
		evidence: "A JWT-shaped token was detected in source.",
		cwe: ["CWE-798"],
		owasp: ["A07:2021-Identification and Authentication Failures"],
		remediationHint:
			"Remove hard-coded tokens and use short-lived runtime credentials or test fixtures with obvious dummy values.",
	},
];

const SCORE_RULES: ScoreRule[] = [
	{
		id: "secret.env-file",
		name: "Environment files must not be uploaded",
		run: (context) =>
			context.files
				.filter((file) => isEnvFile(file.path.toLowerCase()))
				.map((file) =>
					buildFinding("secret.env-file", {
						category: "secret",
						severity: "critical",
						title: "Environment file included in uploaded source",
						evidence: "A .env-style file is present in the zip.",
						file: file.path,
						confidence: "high",
						cwe: ["CWE-200", "CWE-798"],
						owasp: ["A05:2021-Security Misconfiguration"],
						remediationHint:
							"Remove .env files from submitted source, rotate exposed values, and keep only .env.example templates in source control.",
					}),
				),
	},
	{
		id: "secret.patterns",
		name: "Known secret and high-entropy credential patterns",
		run: (context) => context.files.flatMap(findSecretPatternFindings),
	},
	{
		id: "payment.webhook-signature",
		name: "Payment webhooks must verify signatures over raw body",
		run: (context) => context.files.flatMap(findWebhookFindings),
	},
	{
		id: "auth.admin-guard",
		name: "Admin routes must enforce server-side auth and role checks",
		run: findAdminGuardFindings,
	},
	{
		id: "upload.validation",
		name: "Upload handlers must validate file size/type and avoid public or user-named storage",
		run: (context) => context.files.flatMap(findUploadFindings),
	},
	{
		id: "auth.cookie-flags",
		name: "Session cookies must use defensive attributes",
		run: (context) => context.files.flatMap(findCookieFindings),
	},
	{
		id: "dependency.lockfile",
		name: "Dependency lockfiles should be included",
		run: (context) => {
			if (hasAnyLockfile(context.filePaths)) return [];
			return [
				buildFinding("dependency.lockfile", {
					category: "dependency",
					severity: "low",
					title: "No dependency lockfile found",
					evidence:
						"A lockfile helps produce repeatable installs and enables dependency vulnerability scanning.",
					confidence: "medium",
					cwe: ["CWE-1104"],
					owasp: ["A06:2021-Vulnerable and Outdated Components"],
					remediationHint:
						"Commit the package manager lockfile and scan it in CI with npm audit, OSV, Snyk, or an equivalent tool.",
				}),
			];
		},
	},
];

function buildFinding(
	ruleId: string,
	finding: ScoreFindingDraft,
): ScoreFinding {
	return {
		source: finding.source ?? "heuristic",
		ruleId,
		category: finding.category,
		severity: finding.severity,
		title: finding.title,
		evidence: finding.evidence,
		file: finding.file,
		confidence: finding.confidence,
		cwe: finding.cwe,
		owasp: finding.owasp,
		remediationHint: finding.remediationHint,
	};
}

function dedupeFindings(findings: ScoreFinding[]) {
	const seen = new Set<string>();
	return findings.filter((finding) => {
		const key = [
			finding.ruleId,
			finding.category,
			finding.severity,
			finding.title,
			finding.file ?? "",
		].join("|");
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

type ScoringAdjustment = {
	kind: string;
	count: number;
	description: string;
};

function refineFindingsForScoring(findings: ScoreFinding[]): {
	findings: ScoreFinding[];
	adjustments: ScoringAdjustment[];
} {
	const adjustments: ScoringAdjustment[] = [];
	const externalSecretDeduped = dedupeExternalSecretFindings(findings);
	if (externalSecretDeduped.removedCount > 0) {
		adjustments.push({
			kind: "external-secret-location-dedupe",
			count: externalSecretDeduped.removedCount,
			description:
				"Duplicate secret findings from multiple external scanners at the same location were counted once.",
		});
	}

	const heuristicSecretDeduped =
		suppressHeuristicSecretsCoveredByExternalScanners(
			externalSecretDeduped.findings,
		);
	if (heuristicSecretDeduped.removedCount > 0) {
		adjustments.push({
			kind: "heuristic-secret-overlap",
			count: heuristicSecretDeduped.removedCount,
			description:
				"Broad heuristic secret signals were not double-counted when a dedicated scanner reported a secret in the same file.",
		});
	}

	const dependencyDeduped = dedupeOsvDependencyVulnerabilities(
		heuristicSecretDeduped.findings,
	);
	if (dependencyDeduped.removedCount > 0) {
		adjustments.push({
			kind: "dependency-vulnerability-dedupe",
			count: dependencyDeduped.removedCount,
			description:
				"The same dependency vulnerability reported from multiple manifests or lockfiles was counted once.",
		});
	}

	return { findings: dependencyDeduped.findings, adjustments };
}

function dedupeExternalSecretFindings(findings: ScoreFinding[]) {
	const bestByLocation = new Map<string, ScoreFinding>();
	const duplicateExternalSecrets = new Set<ScoreFinding>();

	for (const finding of findings) {
		if (!isExternalSecretFinding(finding)) continue;
		const key = findingLocationKey(finding);
		if (!key) continue;
		const existing = bestByLocation.get(key);
		if (!existing) {
			bestByLocation.set(key, finding);
			continue;
		}
		if (
			secretScannerPriority(finding.source) >
			secretScannerPriority(existing.source)
		) {
			duplicateExternalSecrets.add(existing);
			bestByLocation.set(key, finding);
		} else {
			duplicateExternalSecrets.add(finding);
		}
	}

	return {
		findings: findings.filter(
			(finding) => !duplicateExternalSecrets.has(finding),
		),
		removedCount: duplicateExternalSecrets.size,
	};
}

function suppressHeuristicSecretsCoveredByExternalScanners(
	findings: ScoreFinding[],
) {
	const externalSecretFiles = new Set(
		findings
			.filter(isExternalSecretFinding)
			.map((finding) => normalizeFindingPath(finding.file))
			.filter(Boolean),
	);
	let removedCount = 0;
	const refined = findings.filter((finding) => {
		if (
			finding.source === "heuristic" &&
			finding.category === "secret" &&
			finding.ruleId === "secret.patterns" &&
			externalSecretFiles.has(normalizeFindingPath(finding.file))
		) {
			removedCount += 1;
			return false;
		}
		return true;
	});
	return { findings: refined, removedCount };
}

function dedupeOsvDependencyVulnerabilities(findings: ScoreFinding[]) {
	const bestByVulnerability = new Map<string, ScoreFinding>();
	const duplicates = new Set<ScoreFinding>();

	for (const finding of findings) {
		if (finding.source !== "osv" || finding.category !== "dependency") continue;
		const key = osvDependencyVulnerabilityKey(finding);
		if (!key) continue;
		const existing = bestByVulnerability.get(key);
		if (!existing) {
			bestByVulnerability.set(key, finding);
			continue;
		}
		if (preferOsvFinding(finding, existing)) {
			duplicates.add(existing);
			bestByVulnerability.set(key, finding);
		} else {
			duplicates.add(finding);
		}
	}

	return {
		findings: findings.filter((finding) => !duplicates.has(finding)),
		removedCount: duplicates.size,
	};
}

function osvDependencyVulnerabilityKey(finding: ScoreFinding) {
	const details = parseOsvEvidence(finding.evidence);
	if (!details) return undefined;
	return [
		finding.ruleId ?? finding.title,
		details.ecosystem,
		details.packageName,
		details.version,
	].join("|");
}

function parseOsvEvidence(evidence: string) {
	const match = /^(.+?) - ([^:]+):(.+):(.*?) - scope:([a-z-]+)$/.exec(evidence);
	if (!match) return undefined;
	return {
		path: match[1],
		ecosystem: match[2],
		packageName: match[3],
		version: match[4],
		scope: match[5],
	};
}

function preferOsvFinding(candidate: ScoreFinding, existing: ScoreFinding) {
	const candidateDetails = parseOsvEvidence(candidate.evidence);
	const existingDetails = parseOsvEvidence(existing.evidence);
	if (!candidateDetails || !existingDetails) return false;
	if (
		candidateDetails.scope === "direct-manifest" &&
		existingDetails.scope !== "direct-manifest"
	)
		return true;
	if (
		candidateDetails.scope !== "direct-manifest" &&
		existingDetails.scope === "direct-manifest"
	)
		return false;
	return candidateDetails.path.length < existingDetails.path.length;
}

function isExternalSecretFinding(finding: ScoreFinding) {
	return (
		finding.category === "secret" &&
		(finding.source === "gitleaks" ||
			finding.source === "semgrep" ||
			finding.source === "sarif")
	);
}

function secretScannerPriority(source: ScoreFinding["source"]) {
	if (source === "gitleaks") return 3;
	if (source === "semgrep") return 2;
	if (source === "sarif") return 1;
	return 0;
}

function findingLocationKey(finding: ScoreFinding) {
	const file = normalizeFindingPath(finding.file);
	if (!file) return undefined;
	const line = extractLineNumber(finding.evidence, file);
	return line
		? `${file}:${line}`
		: `${file}:${finding.ruleId ?? finding.title}`;
}

function extractLineNumber(evidence: string, file: string) {
	const escapedFile = file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	const match = new RegExp(`${escapedFile}:(\\d+)`).exec(evidence);
	return match?.[1];
}

function normalizeFindingPath(path: string | undefined) {
	return path?.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
}

function findSecretPatternFindings(file: ScoreInputFile) {
	const findings: ScoreFinding[] = [];
	for (const detector of SECRET_DETECTORS) {
		if (!detector.pattern.test(file.content)) continue;
		detector.pattern.lastIndex = 0;
		findings.push(
			buildFinding("secret.patterns", {
				category: "secret",
				severity: detector.severity,
				title: detector.title,
				evidence: detector.evidence,
				file: file.path,
				confidence: detector.confidence,
				cwe: detector.cwe,
				owasp: detector.owasp,
				remediationHint: detector.remediationHint,
			}),
		);
	}

	if (containsCredentialAssignment(file.content)) {
		findings.push(
			buildFinding("secret.patterns", {
				category: "secret",
				severity: "high",
				title: "Potential secret value found in source",
				evidence:
					"A credential-like assignment was detected. Values are not stored in the public summary.",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-798"],
				owasp: ["A05:2021-Security Misconfiguration"],
				remediationHint:
					"Move the value to a server-only secret store, rotate it if it was real, and keep only dummy placeholders in examples.",
			}),
		);
	}

	if (containsHighEntropyCredential(file.content)) {
		findings.push(
			buildFinding("secret.patterns", {
				category: "secret",
				severity: "medium",
				title: "High-entropy credential-like value found",
				evidence:
					"A long high-entropy value assigned to a key/token/secret-like variable was detected.",
				file: file.path,
				confidence: "low",
				cwe: ["CWE-798"],
				owasp: ["A05:2021-Security Misconfiguration"],
				remediationHint:
					"Review whether this is a real secret, rotate it if needed, and replace committed values with placeholders.",
			}),
		);
	}

	return findings;
}

function containsCredentialAssignment(content: string) {
	const assignmentPattern =
		/\b(database_url|api[_-]?key|secret|token|access[_-]?key|private[_-]?key|password|passwd|client[_-]?secret)\b\s*[:=]\s*(?:(['"])([^'"\r\n]{8,})\2|([^\s,;`]{8,}))/gi;
	for (const match of content.matchAll(assignmentPattern)) {
		const value = (match[3] ?? match[4] ?? "").trim();
		if (looksLikeSecretLiteral(value)) return true;
	}
	return false;
}

function looksLikeSecretLiteral(value: string) {
	const cleaned = value.replace(/[)}\]]+$/, "");
	if (!cleaned || looksLikePlaceholder(cleaned)) return false;
	if (
		/^(process\.env|env\.|params\.|validation\.|values\.|formdata\.|request\.|locals\.)/i.test(
			cleaned,
		)
	)
		return false;
	if (/^[a-z_$][\w$]*(?:\.[a-z_$][\w$]*)+$/i.test(cleaned)) return false;
	if (/^[a-z_$][\w$]*\([^)]*\)$/i.test(cleaned)) return false;
	if (/^\$[{(]?[a-z_][\w]*[)}]?$/i.test(cleaned)) return false;
	if (/^(true|false|null|undefined)$/i.test(cleaned)) return false;
	return (
		/[:/=@]|[A-Z0-9_-]{16,}/.test(cleaned) ||
		(/[a-z]/i.test(cleaned) && /\d/.test(cleaned) && cleaned.length >= 12) ||
		shannonEntropy(cleaned) >= 3.5
	);
}

function containsHighEntropyCredential(content: string) {
	const assignmentPattern =
		/\b(?:api[_-]?key|secret|token|password|credential|client[_-]?secret)\b\s*[:=]\s*['"]([^'"\s]{32,})['"]/gi;
	for (const match of content.matchAll(assignmentPattern)) {
		const value = match[1];
		if (!looksLikePlaceholder(value) && shannonEntropy(value) >= 4) return true;
	}
	return false;
}

function shannonEntropy(value: string) {
	const counts = new Map<string, number>();
	for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
	return Array.from(counts.values()).reduce((entropy, count) => {
		const probability = count / value.length;
		return entropy - probability * Math.log2(probability);
	}, 0);
}

function looksLikePlaceholder(value: string) {
	return /^(changeme|change_me|example|placeholder|dummy|test|your[_-]?)/i.test(
		value,
	);
}

function findWebhookFindings(file: ScoreInputFile) {
	const lowerPath = file.path.toLowerCase();
	const lowerContent = file.content.toLowerCase();
	if (!looksLikeWebhookHandler(lowerPath, lowerContent)) return [];

	const findings: ScoreFinding[] = [];
	const hasSignatureHeader = hasWebhookSignatureHeader(lowerContent);
	const hasVerification = hasWebhookSignatureVerification(lowerContent);
	const usesRawBody = hasRawWebhookBody(lowerContent);

	if (!hasSignatureHeader || !hasVerification) {
		findings.push(
			buildFinding("payment.webhook-signature", {
				category: "payment",
				severity: "high",
				title: "Webhook handler may be missing signature verification",
				evidence:
					"Webhook-related code was found without provider signature header and verification markers.",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-345"],
				owasp: [
					"A01:2021-Broken Access Control",
					"A08:2021-Software and Data Integrity Failures",
				],
				remediationHint:
					"Verify the provider signature on the raw request body before trusting event type, metadata, or payment status.",
			}),
		);
	}

	if (hasSignatureHeader && hasVerification && !usesRawBody) {
		findings.push(
			buildFinding("payment.webhook-signature", {
				category: "payment",
				severity: "medium",
				title: "Webhook verification may not use the raw request body",
				evidence:
					"Signature markers were found, but the handler appears to parse JSON instead of using request.text() or arrayBuffer().",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-347"],
				owasp: ["A08:2021-Software and Data Integrity Failures"],
				remediationHint:
					"Use the exact raw body bytes/string required by the provider's webhook verification API.",
			}),
		);
	}

	if (
		looksLikePaymentStateMutation(lowerContent) &&
		!hasWebhookReplayProtection(lowerContent)
	) {
		findings.push(
			buildFinding("payment.webhook-signature", {
				category: "payment",
				severity: "medium",
				title:
					"Payment webhook may be missing replay or idempotency protection",
				evidence:
					"The handler appears to mutate payment/order state without event idempotency markers.",
				file: file.path,
				confidence: "low",
				cwe: ["CWE-294"],
				owasp: ["A04:2021-Insecure Design"],
				remediationHint:
					"Store processed provider event IDs and ignore duplicates before applying state changes or granting credits.",
			}),
		);
	}

	return findings;
}

function looksLikeWebhookHandler(path: string, content: string) {
	const haystack = `${path}\n${content}`;
	const hasWebhookSignal =
		path.includes("webhook") ||
		content.includes("webhook") ||
		content.includes("stripe-signature") ||
		content.includes("webhook-signature") ||
		content.includes("paypal-transmission-sig");
	if (!hasWebhookSignal) return false;
	if (!looksLikePaymentProviderContext(haystack)) return false;
	return isServerRouteFile(path) || hasHttpWebhookEndpointMarker(content);
}

function looksLikePaymentProviderContext(content: string) {
	return /stripe|polar|paypal|toss|checkout|invoice|payment|order|webhook-signature|stripe-signature|paypal-transmission/.test(
		content,
	);
}

function hasHttpWebhookEndpointMarker(content: string) {
	return (
		/export\s+(const|async\s+function|function)\s+(post|POST)\b/.test(
			content,
		) ||
		/\b(app|router|fastify)\s*\.\s*post\s*\(/.test(content) ||
		/\bnew\s+Response\s*\(/.test(content)
	);
}

function hasWebhookSignatureHeader(content: string) {
	return [
		"stripe-signature",
		"webhook-signature",
		"webhook-timestamp",
		"webhook-id",
		"svix-signature",
		"x-signature",
		"toss-payments-signature",
		"paypal-transmission-sig",
	].some((marker) => content.includes(marker));
}

function hasWebhookSignatureVerification(content: string) {
	return [
		"constructevent",
		"validateevent",
		"webhookverificationerror",
		"webhooksecret",
		"verifywebhook",
		"verify(",
		"createhmac",
		"timingsafeequal",
		"hmac",
		"svix",
	].some((marker) => content.includes(marker));
}

function hasRawWebhookBody(content: string) {
	return (
		content.includes("request.text(") ||
		content.includes("arraybuffer(") ||
		content.includes("rawbody") ||
		content.includes("raw_body") ||
		content.includes("buffer.from")
	);
}

function looksLikePaymentStateMutation(content: string) {
	return (
		/(order|payment|checkout|invoice)\.(paid|completed|succeeded)/.test(
			content,
		) ||
		(/(update|insert|grant|credit|status)/.test(content) &&
			/(payment|order|checkout|invoice|credit)/.test(content))
	);
}

function hasWebhookReplayProtection(content: string) {
	return [
		"idempotency",
		"idempotent",
		"event.id",
		"eventid",
		"webhookid",
		"webhook_id",
		"processed",
		"unique",
		"on conflict",
		"upsert",
	].some((marker) => content.includes(marker));
}

function findAdminGuardFindings(context: AnalysisContext) {
	const globalGuard = hasGlobalAdminGuard(context);
	return context.files.flatMap((file) => {
		if (!isAdminRoutePath(file.path)) return [];
		if (isClientOnlyRouteFile(file.path)) {
			if (globalGuard || hasNearbyServerGuard(file.path, context)) return [];
			return [
				buildFinding("auth.admin-guard", {
					category: "auth",
					severity: "medium",
					title: "Admin page may rely on client-side gating only",
					evidence:
						"An admin Svelte page was found without a nearby +page.server/+layout.server guard.",
					file: file.path,
					confidence: "low",
					cwe: ["CWE-602", "CWE-862"],
					owasp: ["A01:2021-Broken Access Control"],
					remediationHint:
						"Add a server load/action guard or global hook that rejects non-admin users before page data or API work runs.",
				}),
			];
		}

		if (!isServerRouteFile(file.path)) return [];
		const lowerContent = file.content.toLowerCase();
		if (globalGuard && hasRoleCheck(lowerContent)) return [];
		if (!hasServerAuthGuard(lowerContent) && !globalGuard) {
			return [
				buildFinding("auth.admin-guard", {
					category: "auth",
					severity: "high",
					title: "Admin route may be missing a server-side guard",
					evidence:
						"Admin-related server code does not include common session/user guard markers.",
					file: file.path,
					confidence: "medium",
					cwe: ["CWE-862"],
					owasp: ["A01:2021-Broken Access Control"],
					remediationHint:
						"Require an authenticated user on the server before executing admin loaders, actions, or API handlers.",
				}),
			];
		}
		if (!hasRoleCheck(lowerContent) && !globalGuard) {
			return [
				buildFinding("auth.admin-guard", {
					category: "auth",
					severity: "medium",
					title: "Admin route may authenticate users without checking role",
					evidence:
						"The route has authentication markers but no clear admin role or permission check.",
					file: file.path,
					confidence: "medium",
					cwe: ["CWE-863"],
					owasp: ["A01:2021-Broken Access Control"],
					remediationHint:
						"Check an authoritative server-side role/permission, not just login state, before allowing admin operations.",
				}),
			];
		}
		return [];
	});
}

function isAdminRoutePath(path: string) {
	const lowerPath = path.toLowerCase();
	return lowerPath.split("/").some((segment) => segment === "admin");
}

function isClientOnlyRouteFile(path: string) {
	return path.toLowerCase().endsWith(".svelte");
}

function isServerRouteFile(path: string) {
	const lowerPath = path.toLowerCase();
	return (
		lowerPath.endsWith("+server.ts") ||
		lowerPath.endsWith("+page.server.ts") ||
		lowerPath.endsWith("+layout.server.ts") ||
		lowerPath.endsWith(".server.ts")
	);
}

function hasNearbyServerGuard(path: string, context: AnalysisContext) {
	const segments = path.split("/");
	const fileName = segments.pop();
	if (!fileName?.endsWith(".svelte")) return false;
	for (let end = segments.length; end >= 1; end -= 1) {
		const directory = segments.slice(0, end).join("/");
		for (const candidate of [
			`${directory}/+page.server.ts`,
			`${directory}/+layout.server.ts`,
		]) {
			const serverFile = context.filesByPath.get(candidate);
			if (
				serverFile &&
				(hasServerAuthGuard(serverFile.content.toLowerCase()) ||
					hasRoleCheck(serverFile.content.toLowerCase()))
			)
				return true;
		}
	}
	return false;
}

function hasGlobalAdminGuard(context: AnalysisContext) {
	return context.files.some((file) => {
		if (!file.path.toLowerCase().endsWith("hooks.server.ts")) return false;
		const content = file.content.toLowerCase();
		return (
			content.includes("admin") &&
			hasServerAuthGuard(content) &&
			(hasRoleCheck(content) ||
				content.includes("403") ||
				content.includes("401"))
		);
	});
}

function hasServerAuthGuard(content: string) {
	return [
		"locals.user",
		"locals.session",
		"session",
		"requireauth",
		"require_auth",
		"authenticate",
		"authorized",
		"redirect(303",
		"redirect(302",
		"error(401",
		"error(403",
		"fail(401",
		"fail(403",
	].some((marker) => content.includes(marker));
}

function hasRoleCheck(content: string) {
	return [
		"isadmin",
		"is_admin",
		"requireadmin",
		"require_admin",
		"role",
		"roles",
		"permission",
		"permissions",
		"haspermission",
		"user.role",
		"user.type",
	].some((marker) => content.includes(marker));
}

function findUploadFindings(file: ScoreInputFile) {
	const lowerPath = file.path.toLowerCase();
	const lowerContent = file.content.toLowerCase();
	if (!looksLikeUploadHandler(lowerPath, lowerContent)) return [];

	const findings: ScoreFinding[] = [];
	if (!hasUploadValidation(lowerContent)) {
		findings.push(
			buildFinding("upload.validation", {
				category: "upload",
				severity: "medium",
				title: "Upload handler may be missing file validation",
				evidence:
					"File/form-data handling was found without clear size or type validation markers.",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-20", "CWE-434"],
				owasp: ["A03:2021-Injection", "A05:2021-Security Misconfiguration"],
				remediationHint:
					"Validate file size, extension, and content type on the server before storing or processing uploads.",
			}),
		);
	}

	if (
		usesUserControlledUploadName(lowerContent) &&
		!usesGeneratedFileName(lowerContent)
	) {
		findings.push(
			buildFinding("upload.validation", {
				category: "upload",
				severity: "high",
				title: "Upload storage may use a user-controlled file name",
				evidence:
					"Storage path/key code appears to include file.name or original filename without a generated safe name marker.",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-22", "CWE-73"],
				owasp: [
					"A01:2021-Broken Access Control",
					"A05:2021-Security Misconfiguration",
				],
				remediationHint:
					"Generate a server-side object key, store the original name only as metadata, and normalize/reject path separators.",
			}),
		);
	}

	if (storesUploadsInPublicPath(lowerContent)) {
		findings.push(
			buildFinding("upload.validation", {
				category: "upload",
				severity: "medium",
				title: "Uploads may be stored in a public/static path",
				evidence:
					"Upload handling code references public/static storage locations or public URLs.",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-200", "CWE-552"],
				owasp: [
					"A01:2021-Broken Access Control",
					"A05:2021-Security Misconfiguration",
				],
				remediationHint:
					"Store untrusted uploads in private object storage or non-public directories and serve through authorized download endpoints.",
			}),
		);
	}

	if (
		looksLikeArchiveExtraction(lowerContent) &&
		!hasZipTraversalDefense(lowerContent)
	) {
		findings.push(
			buildFinding("upload.validation", {
				category: "upload",
				severity: "high",
				title: "Archive extraction may be missing path traversal defense",
				evidence:
					"Archive extraction markers were found without path normalization or .. segment rejection markers.",
				file: file.path,
				confidence: "low",
				cwe: ["CWE-22"],
				owasp: ["A01:2021-Broken Access Control"],
				remediationHint:
					"Normalize every archive entry path, reject absolute/drive/.. paths, and write only below an intended extraction root.",
			}),
		);
	}

	return findings;
}

function looksLikeUploadHandler(path: string, content: string) {
	return (
		path.includes("upload") ||
		content.includes("multipart") ||
		content.includes(" instanceof file") ||
		content.includes("sourcezip") ||
		/\bformdata\(\)[\s\S]{0,500}\b(file|sourcezip|arraybuffer|blob)\b/.test(
			content,
		) ||
		(content.includes("arraybuffer()") && content.includes("writefile")) ||
		content.includes("putobjectcommand")
	);
}

function hasUploadValidation(content: string) {
	return [
		"maxbytes",
		"max_bytes",
		"maxfilebytes",
		"max_file_bytes",
		"maxsize",
		"max_size",
		"size >",
		"file.size",
		"filesize",
		"content-type",
		"contenttype",
		"mimetype",
		"mime",
		"endswith",
		"accept=",
		"validatezipfile",
		"validate scorerequest",
	].some((marker) => content.includes(marker));
}

function usesUserControlledUploadName(content: string) {
	return /(?:writefile|creatwritestream|putobjectcommand|key:|join\s*\()[\s\S]{0,160}(?:file\.name|originalfilename|original_file_name|filename)/i.test(
		content,
	);
}

function usesGeneratedFileName(content: string) {
	return [
		"randomuuid",
		"crypto.randomuuid",
		"safeid",
		"builduploadfilename",
		"buildscoreuploadfilename",
		"storedfilename",
		"sanitize",
		"slugify",
		"uuid",
	].some((marker) => content.includes(marker));
}

function storesUploadsInPublicPath(content: string) {
	return (
		/(?:static|public)\/(?:uploads|files|assets)/.test(content) ||
		/(?:uploads|files)\/(?:public)/.test(content) ||
		content.includes("publicurl") ||
		content.includes("public_url")
	);
}

function looksLikeArchiveExtraction(content: string) {
	return [
		"adm-zip",
		"jszip",
		"yauzl",
		"unzipper",
		"extractallto",
		"entry.path",
		"central directory",
	].some((marker) => content.includes(marker));
}

function hasZipTraversalDefense(content: string) {
	return [
		"normalize",
		"normalized",
		"safepath",
		"safe_path",
		"path traversal",
		"..",
		'startswith("/")',
		"startsWith('/')".toLowerCase(),
		"segments.some",
	].some((marker) => content.includes(marker));
}

function findCookieFindings(file: ScoreInputFile) {
	const lowerContent = file.content.toLowerCase();
	if (!lowerContent.includes("cookies.set")) return [];

	const findings: ScoreFinding[] = [];
	if (!lowerContent.includes("httponly")) {
		findings.push(
			buildFinding("auth.cookie-flags", {
				category: "auth",
				severity: "medium",
				title: "Cookie may be missing httpOnly protection",
				evidence:
					"Cookie assignment was detected without an httpOnly marker nearby.",
				file: file.path,
				confidence: "medium",
				cwe: ["CWE-1004"],
				owasp: ["A05:2021-Security Misconfiguration"],
				remediationHint:
					"Set httpOnly: true for session cookies so browser JavaScript cannot read them.",
			}),
		);
	}
	if (!lowerContent.includes("secure")) {
		findings.push(
			buildFinding("auth.cookie-flags", {
				category: "auth",
				severity: "low",
				title: "Cookie may be missing secure flag",
				evidence:
					"Cookie assignment was detected without a secure marker nearby.",
				file: file.path,
				confidence: "low",
				cwe: ["CWE-614"],
				owasp: ["A05:2021-Security Misconfiguration"],
				remediationHint:
					"Set secure: true in production so cookies are sent only over HTTPS.",
			}),
		);
	}
	if (!lowerContent.includes("samesite")) {
		findings.push(
			buildFinding("auth.cookie-flags", {
				category: "auth",
				severity: "low",
				title: "Cookie may be missing SameSite protection",
				evidence:
					"Cookie assignment was detected without a sameSite marker nearby.",
				file: file.path,
				confidence: "low",
				cwe: ["CWE-352"],
				owasp: ["A01:2021-Broken Access Control"],
				remediationHint:
					"Set sameSite to 'lax' or 'strict' for session cookies unless cross-site flows explicitly require otherwise.",
			}),
		);
	}
	return findings;
}

function hasAnyLockfile(paths: string[]) {
	return paths.some((path) =>
		IMPORTANT_FILE_NAMES.has(
			path.toLowerCase().split("/").pop() ?? path.toLowerCase(),
		),
	);
}

function calculateScoreBreakdown(findings: ScoreFinding[]): ScoreBreakdown {
	const bySource: ScoreBreakdown["bySource"] = {};
	const bySeverity: ScoreBreakdown["bySeverity"] = {};
	const byCategory: ScoreBreakdown["byCategory"] = {};
	const findingsBySource: Record<string, ScoreFinding[]> = {};

	for (const finding of findings) {
		const penalty = severityPenalty(finding.severity);
		const source = finding.source;
		const sourceBucket = bySource[source] ?? {
			findingCount: 0,
			rawPenalty: 0,
			cappedPenalty: 0,
			cap: SOURCE_PENALTY_CAPS[source],
			severityCounts: {},
		};
		findingsBySource[source] = [...(findingsBySource[source] ?? []), finding];
		sourceBucket.findingCount += 1;
		sourceBucket.rawPenalty += penalty;
		sourceBucket.severityCounts[finding.severity] =
			(sourceBucket.severityCounts[finding.severity] ?? 0) + 1;
		bySource[source] = sourceBucket;

		const severityBucket = bySeverity[finding.severity] ?? {
			findingCount: 0,
			penalty: 0,
		};
		severityBucket.findingCount += 1;
		severityBucket.penalty += penalty;
		bySeverity[finding.severity] = severityBucket;

		const categoryBucket = byCategory[finding.category] ?? {
			findingCount: 0,
			rawPenalty: 0,
			severityCounts: {},
		};
		categoryBucket.findingCount += 1;
		categoryBucket.rawPenalty += penalty;
		categoryBucket.severityCounts[finding.severity] =
			(categoryBucket.severityCounts[finding.severity] ?? 0) + 1;
		byCategory[finding.category] = categoryBucket;
	}

	let rawPenalty = 0;
	let cappedPenalty = 0;
	for (const [source, bucket] of Object.entries(bySource)) {
		bucket.cap = getEffectiveSourcePenaltyCap(
			source as ScoreFinding["source"],
			findingsBySource[source] ?? [],
		);
		bucket.cappedPenalty = Math.min(bucket.rawPenalty, bucket.cap);
		rawPenalty += bucket.rawPenalty;
		cappedPenalty += bucket.cappedPenalty;
		bySource[source] = bucket;
	}

	const score = Math.max(0, 100 - cappedPenalty);
	return {
		modelVersion: SCORE_MODEL_VERSION,
		baseScore: 100,
		score,
		rawPenalty,
		cappedPenalty,
		...(score === 0
			? {
					zeroScoreReason:
						"Capped scanner penalties reached or exceeded the full 100-point score budget.",
				}
			: {}),
		sourceCaps: SOURCE_PENALTY_CAPS,
		bySource,
		bySeverity,
		byCategory,
	};
}

function getEffectiveSourcePenaltyCap(
	source: ScoreFinding["source"],
	findings: ScoreFinding[],
) {
	if (source === "osv" && findings.length > 0) {
		const scopes = new Set(findings.map(getOsvDependencyScopeFromFinding));
		if (scopes.size === 1 && scopes.has("lockfile")) return 15;
	}
	return SOURCE_PENALTY_CAPS[source];
}

function getOsvDependencyScopeFromFinding(finding: ScoreFinding) {
	const match = /(?:^|\b)scope:([a-z-]+)/.exec(finding.evidence);
	return match?.[1] ?? "unknown";
}

export const SEVERITY_PENALTIES: Record<ScoreFinding["severity"], number> = {
	critical: 25,
	high: 12,
	medium: 6,
	low: 2,
	info: 0,
};

function severityPenalty(severity: ScoreFinding["severity"]) {
	return SEVERITY_PENALTIES[severity] ?? 0;
}

function attachScannerScoreImpact(
	scannerResults: Record<string, unknown>,
	scoreBreakdown: ScoreBreakdown,
) {
	return Object.fromEntries(
		Object.entries(scannerResults).map(([scanner, value]) => {
			const sourceImpact = scoreBreakdown.bySource[scanner];
			return [
				scanner,
				{
					...(isRecord(value) ? value : { value }),
					...(sourceImpact
						? {
								scoreImpact: {
									rawPenalty: sourceImpact.rawPenalty,
									cappedPenalty: sourceImpact.cappedPenalty,
									cap: sourceImpact.cap,
									findingCount: sourceImpact.findingCount,
									severityCounts: sourceImpact.severityCounts,
								},
							}
						: {}),
				},
			];
		}),
	);
}

function getRiskLevel(score: number, findings: ScoreFinding[]) {
	if (findings.some((finding) => finding.severity === "critical") || score < 50)
		return "Critical launch risk";
	if (score < 70 || findings.some((finding) => finding.severity === "high"))
		return "High launch risk";
	if (score < 85 || findings.some((finding) => finding.severity === "medium"))
		return "Medium launch risk";
	return "Low launch risk";
}

function buildHeadline(score: number, findings: ScoreFinding[]) {
	if (findings.length === 0)
		return "No major launch-risk signals were detected in the preliminary scan.";
	return `Preliminary scan found ${findings.length} launch-risk signal${findings.length === 1 ? "" : "s"} with a score of ${score}/100.`;
}

function buildSummaryReasons(findings: ScoreFinding[]) {
	const seen = new Set<string>();
	const reasons: string[] = [];
	for (const finding of findings) {
		const key = `${finding.category}|${finding.title}`;
		if (seen.has(key)) continue;
		seen.add(key);
		reasons.push(finding.title);
		if (reasons.length === 5) break;
	}
	return reasons;
}

function chooseRecommendedPlan(
	findings: ScoreFinding[],
): "Quick Scan" | "Full Audit" | "Launch Audit" {
	if (findings.some((finding) => finding.severity === "critical"))
		return "Full Audit";
	if (findings.filter((finding) => finding.severity === "high").length >= 2)
		return "Full Audit";
	if (
		findings.some(
			(finding) =>
				finding.category === "payment" || finding.category === "auth",
		)
	)
		return "Quick Scan";
	return "Quick Scan";
}
