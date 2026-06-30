// Upload zip validation + safety checks: extension/size, zip-bomb limits,
// path-traversal rejection, and (optionally) forbidden secret files. Pure —
// operates on a File/Buffer, no storage or platform deps.

type UploadCandidate = {
	name: string;
	size: number;
};

export const DEFAULT_UPLOAD_LIMIT_BYTES = 3 * 1024 * 1024;

export function validateZipFile(file: UploadCandidate, maxBytes: number) {
	if (!file.name.toLowerCase().endsWith(".zip")) {
		return { ok: false, error: "Only zip files are accepted." };
	}

	if (file.size === 0) {
		return { ok: false, error: "The uploaded zip file is empty." };
	}

	if (file.size > maxBytes) {
		return {
			ok: false,
			error: `File size exceeds the ${formatBytes(maxBytes)} limit.`,
		};
	}

	return { ok: true };
}

export type SourceZipSecurityLimits = {
	maxFiles: number;
	maxEntryBytes: number;
	maxTotalUncompressedBytes: number;
	maxCompressionRatio: number;
};

const DEFAULT_SOURCE_ZIP_SECURITY_LIMITS: SourceZipSecurityLimits = {
	maxFiles: 2_000,
	maxEntryBytes: 5 * 1024 * 1024,
	maxTotalUncompressedBytes: 50 * 1024 * 1024,
	maxCompressionRatio: 100,
};

export type SourceZipValidationOptions = {
	// When true, files like .env or private keys are allowed through. Used for
	// whole-repo GitHub scans, where committed secrets are findings the scanner
	// should surface rather than a reason to reject the upload.
	allowSensitiveFiles?: boolean;
};

export async function validateSourceZipUpload(
	file: File,
	maxBytes: number,
	limits: Partial<SourceZipSecurityLimits> = {},
	options: SourceZipValidationOptions = {},
) {
	const base = validateZipFile(file, maxBytes);
	if (!base.ok) return base;

	const effectiveLimits = { ...DEFAULT_SOURCE_ZIP_SECURITY_LIMITS, ...limits };
	let zip: Buffer;
	try {
		zip = Buffer.from(await file.arrayBuffer());
	} catch {
		return { ok: false, error: "Could not read the uploaded zip file." };
	}

	try {
		const summary = inspectZipUpload(zip, effectiveLimits, options);
		if (summary.fileCount === 0) {
			return {
				ok: false,
				error: "The zip archive does not contain any files.",
			};
		}
		return { ok: true };
	} catch (error) {
		return {
			ok: false,
			error:
				error instanceof Error
					? error.message
					: "The uploaded file is not a valid zip archive.",
		};
	}
}

export function getUploadLimitBytes(env: Record<string, string | undefined>) {
	const parsed = Number(env.AUDIT_UPLOAD_MAX_BYTES);
	return Number.isFinite(parsed) && parsed > 0
		? parsed
		: DEFAULT_UPLOAD_LIMIT_BYTES;
}

type ZipUploadSummary = {
	fileCount: number;
	totalUncompressedBytes: number;
};

function inspectZipUpload(
	zip: Buffer,
	limits: SourceZipSecurityLimits,
	options: SourceZipValidationOptions = {},
): ZipUploadSummary {
	const eocdOffset = findEndOfCentralDirectory(zip);
	const centralDirectorySize = zip.readUInt32LE(eocdOffset + 12);
	const centralDirectoryOffset = zip.readUInt32LE(eocdOffset + 16);
	const entryCount = zip.readUInt16LE(eocdOffset + 10);
	if (
		centralDirectorySize === 0xffffffff ||
		centralDirectoryOffset === 0xffffffff ||
		entryCount === 0xffff
	) {
		throw new Error(
			"Zip64 archives are not accepted. Upload a smaller standard zip file.",
		);
	}
	if (centralDirectoryOffset + centralDirectorySize > zip.length) {
		throw new Error("The uploaded file is not a valid zip archive.");
	}

	let cursor = centralDirectoryOffset;
	const end = centralDirectoryOffset + centralDirectorySize;
	let fileCount = 0;
	let totalUncompressedBytes = 0;

	while (cursor < end) {
		if (cursor + 46 > zip.length || zip.readUInt32LE(cursor) !== 0x02014b50) {
			throw new Error("The uploaded file is not a valid zip archive.");
		}

		const flags = zip.readUInt16LE(cursor + 8);
		const compressionMethod = zip.readUInt16LE(cursor + 10);
		const compressedSize = zip.readUInt32LE(cursor + 20);
		const uncompressedSize = zip.readUInt32LE(cursor + 24);
		const nameLength = zip.readUInt16LE(cursor + 28);
		const extraLength = zip.readUInt16LE(cursor + 30);
		const commentLength = zip.readUInt16LE(cursor + 32);
		const localHeaderOffset = zip.readUInt32LE(cursor + 42);
		const nameStart = cursor + 46;
		const nameEnd = nameStart + nameLength;
		const next = nameEnd + extraLength + commentLength;
		if (nameLength === 0 || nameEnd > zip.length || next > zip.length) {
			throw new Error("The uploaded file is not a valid zip archive.");
		}

		const rawPath = zip.subarray(nameStart, nameEnd).toString("utf8");
		const path = normalizeUploadZipPath(rawPath);
		if (!path) {
			throw new Error(
				"The zip contains an unsafe file path. Remove absolute paths, empty segments, or '..' segments.",
			);
		}
		if (flags & 0x1) {
			throw new Error("Password-protected zip files are not accepted.");
		}
		if (compressionMethod !== 0 && compressionMethod !== 8) {
			throw new Error("The zip uses an unsupported compression method.");
		}
		if (localHeaderOffset >= zip.length) {
			throw new Error("The uploaded file is not a valid zip archive.");
		}

		if (!path.endsWith("/")) {
			if (!options.allowSensitiveFiles && isForbiddenUploadPath(path)) {
				throw new Error(
					"The zip contains files that should not be uploaded, such as .env files, private keys, or credential files.",
				);
			}
			fileCount += 1;
			if (fileCount > limits.maxFiles) {
				throw new Error(
					`The zip contains too many files. Limit: ${limits.maxFiles}.`,
				);
			}
			if (uncompressedSize > limits.maxEntryBytes) {
				throw new Error(
					`A file inside the zip is too large. Per-file limit: ${formatBytes(limits.maxEntryBytes)}.`,
				);
			}
			totalUncompressedBytes += uncompressedSize;
			if (totalUncompressedBytes > limits.maxTotalUncompressedBytes) {
				throw new Error(
					`The zip expands to too much data. Expanded limit: ${formatBytes(limits.maxTotalUncompressedBytes)}.`,
				);
			}
			if (
				compressedSize > 0 &&
				uncompressedSize > 1024 * 1024 &&
				uncompressedSize / compressedSize > limits.maxCompressionRatio
			) {
				throw new Error(
					"The zip compression ratio is too high. Upload a normal source archive, not a compressed bomb.",
				);
			}
		}

		cursor = next;
	}

	if (cursor !== end)
		throw new Error("The uploaded file is not a valid zip archive.");
	return { fileCount, totalUncompressedBytes };
}

function findEndOfCentralDirectory(zip: Buffer) {
	const minOffset = Math.max(0, zip.length - 65_557);
	for (let offset = zip.length - 22; offset >= minOffset; offset -= 1) {
		if (zip.readUInt32LE(offset) === 0x06054b50) return offset;
	}
	throw new Error("The uploaded file is not a valid zip archive.");
}

function normalizeUploadZipPath(path: string) {
	const normalized = path.replace(/\\/g, "/").replace(/^\.\//, "");
	if (
		!normalized ||
		normalized.includes("\0") ||
		normalized.startsWith("/") ||
		/^[a-z]:/i.test(normalized)
	) {
		return null;
	}
	const segments = normalized.split("/");
	if (
		segments.some((segment, index) => {
			const isTrailingDirectoryMarker =
				index === segments.length - 1 && segment === "";
			return (
				!isTrailingDirectoryMarker &&
				(!segment || segment === "." || segment === "..")
			);
		})
	) {
		return null;
	}
	return segments.join("/");
}

function isForbiddenUploadPath(path: string) {
	const fileName = path.toLowerCase().split("/").pop() ?? "";
	return (
		fileName === ".env" ||
		fileName.startsWith(".env.") ||
		fileName === ".npmrc" ||
		fileName === ".pypirc" ||
		fileName === ".netrc" ||
		/^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/.test(fileName) ||
		/\.(?:pem|key|p12|pfx)$/i.test(fileName)
	);
}

function formatBytes(bytes: number) {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
	return `${Math.round(bytes / 1024 / 1024)} MB`;
}
