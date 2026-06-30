# Batteries-included image: the oh-my-audit CLI + gitleaks + semgrep + osv-scanner.
# Build:  docker build -t oh-my-audit .
# Run:    docker run --rm -v "$PWD:/src" oh-my-audit scan /src --sarif

# ---- build the CLI -------------------------------------------------------
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json tsup.config.ts ./
COPY src ./src
RUN npm run build

# ---- runtime with scanners ----------------------------------------------
FROM node:20-bookworm-slim AS runtime
ARG GITLEAKS_VERSION=8.18.4
ARG OSV_VERSION=1.9.2
ARG TARGETARCH=amd64

# semgrep (via pip) + tools to fetch the Go-binary scanners
RUN apt-get update \
	&& apt-get install -y --no-install-recommends python3 python3-pip ca-certificates curl tar \
	&& pip3 install --no-cache-dir --break-system-packages semgrep \
	# gitleaks
	&& curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
		| tar -xz -C /usr/local/bin gitleaks \
	# osv-scanner
	&& curl -sSL -o /usr/local/bin/osv-scanner \
		"https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${TARGETARCH}" \
	&& chmod +x /usr/local/bin/osv-scanner \
	&& apt-get purge -y curl tar && apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/dist ./dist
COPY package.json LICENSE README.md ./

# Drop privileges — the scanners run untrusted code paths.
USER node
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["scan", "/src"]
