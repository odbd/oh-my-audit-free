import { defineConfig } from "tsup";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		cli: "src/cli.ts",
	},
	format: ["esm"],
	target: "node20",
	platform: "node",
	dts: { entry: { index: "src/index.ts" } },
	clean: true,
	splitting: false,
	sourcemap: false,
	// The engine has no runtime dependencies; bundle everything into each entry.
	noExternal: [/.*/],
});
