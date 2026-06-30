// Pure transforms that shape stored findings into the user-facing report
// structures (detailed findings list + per-category breakdown).
import { SEVERITY_PENALTIES } from "./scoring";

export type PublicCategoryBreakdownItem = {
	category: string;
	findingCount: number;
	rawPenalty: number;
	severityCounts: Record<string, number>;
};

export type PublicDetailedFinding = {
	category: string;
	severity: string;
	title: string;
	file: string | null;
	evidence: string | null;
	confidence: string | null;
	remediationHint: string | null;
	source: string | null;
	cwe: string[];
	owasp: string[];
};

const SEVERITY_ORDER: Record<string, number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

const MAX_DETAILED_FINDINGS = 300;

// gitleaks is the secret scanner; its findings are committed credentials.
export function isSecretFinding(finding: PublicDetailedFinding): boolean {
	return finding.source === "gitleaks" || finding.category === "secret";
}

// Critical/high findings are surfaced free with location + fix guidance.
export function isHighImpactFinding(finding: PublicDetailedFinding): boolean {
	return finding.severity === "critical" || finding.severity === "high";
}

export function buildDetailedFindings(
	internalFindings: unknown,
): PublicDetailedFinding[] {
	if (!Array.isArray(internalFindings)) return [];
	const findings: PublicDetailedFinding[] = [];
	for (const finding of internalFindings) {
		if (!isRecord(finding)) continue;
		const category = stringValue(finding.category);
		const severity = stringValue(finding.severity);
		const title = stringValue(finding.title);
		if (!category || !severity || !title) continue;
		findings.push({
			category,
			severity,
			title,
			file: stringValue(finding.file) ?? null,
			evidence: stringValue(finding.evidence) ?? null,
			confidence: stringValue(finding.confidence) ?? null,
			remediationHint: stringValue(finding.remediationHint) ?? null,
			source: stringValue(finding.source) ?? null,
			cwe: stringArray(finding.cwe),
			owasp: stringArray(finding.owasp),
		});
	}
	findings.sort(
		(a, b) =>
			(SEVERITY_ORDER[a.severity] ?? Number.MAX_SAFE_INTEGER) -
			(SEVERITY_ORDER[b.severity] ?? Number.MAX_SAFE_INTEGER),
	);
	return findings.slice(0, MAX_DETAILED_FINDINGS);
}

export function buildCategoryBreakdown(
	internalFindings: unknown,
): PublicCategoryBreakdownItem[] {
	if (!Array.isArray(internalFindings)) return [];
	const buckets = new Map<string, PublicCategoryBreakdownItem>();
	for (const finding of internalFindings) {
		if (!isRecord(finding)) continue;
		const category = stringValue(finding.category);
		const severity = stringValue(finding.severity);
		if (!category || !severity) continue;
		const bucket = buckets.get(category) ?? {
			category,
			findingCount: 0,
			rawPenalty: 0,
			severityCounts: {},
		};
		bucket.findingCount += 1;
		bucket.rawPenalty +=
			SEVERITY_PENALTIES[severity as keyof typeof SEVERITY_PENALTIES] ?? 0;
		bucket.severityCounts[severity] =
			(bucket.severityCounts[severity] ?? 0) + 1;
		buckets.set(category, bucket);
	}
	return Array.from(buckets.values()).sort(
		(a, b) => b.rawPenalty - a.rawPenalty || b.findingCount - a.findingCount,
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function stringValue(value: unknown) {
	return typeof value === "string" ? value : undefined;
}

function stringArray(value: unknown) {
	if (!Array.isArray(value)) return [];
	return value.filter((item): item is string => typeof item === "string");
}
