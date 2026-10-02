/** Test doubles for GitHub and Telegram, routed by URL. */

export function fakeFetch(routes) {
	const sent = [];
	const calls = [];
	async function fetchImpl(url, init = {}) {
		calls.push(url);
		if (url.startsWith("https://api.telegram.org/")) {
			sent.push(JSON.parse(init.body));
			return new Response(JSON.stringify({ ok: true }), { status: 200 });
		}
		const path = url.replace("https://api.github.com", "");
		for (const [pattern, value] of routes) {
			const hit = typeof pattern === "string" ? path.startsWith(pattern) : pattern.test(path);
			if (!hit) continue;
			if (value === 404) return new Response("not found", { status: 404 });
			const raw = init.headers?.Accept === "application/vnd.github.raw";
			const body = typeof value === "string" && raw ? value : JSON.stringify(typeof value === "function" ? value(path) : value);
			return new Response(body, { status: 200 });
		}
		return new Response("not found", { status: 404 });
	}
	return { fetchImpl, sent, calls };
}

export const BUILD_VARS = `addon_info = AddonInfo(
	addon_name="AccessifyPlay",
	addon_summary=_("Accessify Play"),
	addon_version="1.12.1",
	addon_minimumNVDAVersion="2025.1",
	addon_lastTestedNVDAVersion="2026.1",
)`;

export const NVDA_VERSIONS = [
	{ description: "NVDA 2025.3", apiVer: { major: 2025, minor: 3, patch: 0 }, backCompatTo: { major: 2025, minor: 1, patch: 0 } },
	{ description: "NVDA 2026.1", apiVer: { major: 2026, minor: 1, patch: 0 }, backCompatTo: { major: 2026, minor: 1, patch: 0 } },
	{ description: "NVDA 2026.3", apiVer: { major: 2026, minor: 3, patch: 0 }, backCompatTo: { major: 2026, minor: 1, patch: 0 }, experimental: true },
];

export function storeEntryJson({ lastTested = { major: 2026, minor: 1, patch: 0 }, malicious = 0, suspicious = 0 } = {}) {
	return JSON.stringify({
		addonId: "AccessifyPlay",
		minNVDAVersion: { major: 2025, minor: 1, patch: 0 },
		lastTestedVersion: lastTested,
		scanResults: { virusTotal: [{ last_analysis_stats: { malicious, suspicious, undetected: 60 } }] },
	});
}

/** An organization with one add-on repo and one other repo. */
export function orgRoutes(extra = []) {
	return [
		...extra,
		["/orgs/InfiArtt/repos", [{ name: "accessify-play", archived: false }, { name: "TeamTalkBot", archived: false }]],
		["/repos/InfiArtt/accessify-play/contents/buildVars.py", BUILD_VARS],
		["/repos/InfiArtt/TeamTalkBot/contents/buildVars.py", 404],
		["/repos/nvaccess/addon-datastore/contents/transform/nvdaAPIVersions.json", JSON.stringify(NVDA_VERSIONS)],
	];
}
