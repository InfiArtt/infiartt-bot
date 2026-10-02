/** Small helpers shared by the rest of the bot. */

/** Escapes text for Telegram's HTML parse mode. */
export function escapeHtml(value) {
	return String(value ?? "")
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;");
}

/** "v1.12.1" or "1.12" -> [1, 12, 1] / [1, 12, 0]; anything else -> null. */
export function parseVersion(value) {
	const m = String(value ?? "").trim().match(/^v?(\d+)\.(\d+)(?:\.(\d+))?$/);
	return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)] : null;
}

/** Orders version strings; unparseable ones sort first. */
export function compareVersions(a, b) {
	const pa = parseVersion(a);
	const pb = parseVersion(b);
	if (!pa || !pb) return (pa ? 1 : 0) - (pb ? 1 : 0);
	for (let i = 0; i < 3; i++) {
		if (pa[i] !== pb[i]) return pa[i] - pb[i];
	}
	return 0;
}

/** {major, minor, patch} as used by the Add-on Store -> "2026.1" / "2026.1.1". */
export function formatApiVersion(v) {
	if (!v) return "?";
	return v.patch ? `${v.major}.${v.minor}.${v.patch}` : `${v.major}.${v.minor}`;
}

/** Compares two {major, minor, patch} objects. */
export function compareApiVersions(a, b) {
	for (const key of ["major", "minor", "patch"]) {
		const d = (a?.[key] ?? 0) - (b?.[key] ?? 0);
		if (d !== 0) return d;
	}
	return 0;
}

/** Shortens text to at most `max` characters, ending with an ellipsis. */
export function truncate(text, max) {
	const s = String(text ?? "").trim();
	return s.length <= max ? s : `${s.slice(0, max - 1).trimEnd()}…`;
}

/** Constant-time string comparison, for secrets. */
export function safeEqual(a, b) {
	const x = String(a ?? "");
	const y = String(b ?? "");
	let diff = x.length ^ y.length;
	for (let i = 0; i < Math.max(x.length, y.length); i++) {
		diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
	}
	return diff === 0;
}
