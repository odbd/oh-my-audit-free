import { describe, expect, it } from "vitest";
import { analyzeScoreFiles } from "./index";

// Heuristic-only smoke tests (no external scanner binaries required), so they
// run anywhere — including CI without gitleaks/semgrep/osv installed.
describe("analyzeScoreFiles", () => {
	it("returns a scored result for clean input", () => {
		const result = analyzeScoreFiles([
			{ path: "readme.txt", content: "hello world" },
		]);
		expect(typeof result.score).toBe("number");
		expect(result.score).toBeGreaterThanOrEqual(0);
		expect(result.score).toBeLessThanOrEqual(100);
		expect(Array.isArray(result.internalFindings)).toBe(true);
		expect(typeof result.riskLevel).toBe("string");
	});

	it("flags an obviously committed secret and lowers the score", () => {
		const result = analyzeScoreFiles([
			{ path: "config.js", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' }, // gitleaks:allow (AWS docs example key, test fixture only)
		]);
		expect(result.internalFindings.length).toBeGreaterThan(0);
		expect(result.score).toBeLessThan(100);
		expect(
			result.internalFindings.some((f) => f.category === "secret"),
		).toBe(true);
	});
});
