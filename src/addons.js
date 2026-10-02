/**
 * NVDA add-on monitoring. Everything here only READS public data from the
 * NV Access Add-on Store repository; the bot never writes there. NV Access
 * asks that submissions and replies are made by people through the issue
 * form, not by tools.
 */
import { compareApiVersions, compareVersions, escapeHtml, formatApiVersion } from "./util.js";

export const STORE = "nvaccess/addon-datastore";
export const SUBMIT_FORM = `https://github.com/${STORE}/issues/new?template=registerAddon.yml`;

function field(source, name) {
	const m = source.match(new RegExp(`${name}\\s*=\\s*(?:_\\(\\s*)?["']([^"'\\n]+)["']`));
	return m ? m[1] : null;
}

/** Every repository in the organization that builds an NVDA add-on. */
export async function findAddonRepos(gh, org) {
	const repos = await gh.all(`/orgs/${org}/repos?type=all`);
	const addons = [];
	for (const repo of repos) {
		if (repo.archived) continue;
		const buildVars = await gh.raw(`/repos/${org}/${repo.name}/contents/buildVars.py`);
		if (!buildVars) continue;
		const name = field(buildVars, "addon_name");
		if (!name) continue;
		addons.push({
			repo: repo.name,
			name,
			summary: field(buildVars, "addon_summary") || name,
			version: field(buildVars, "addon_version"),
			minimumNVDA: field(buildVars, "addon_minimumNVDAVersion"),
			lastTestedNVDA: field(buildVars, "addon_lastTestedNVDAVersion"),
		});
	}
	return addons;
}

/** "2026.1" or "2026.1.1" -> {major, minor, patch}, as the store writes versions. */
export function toApiVersion(text) {
	const m = String(text ?? "").match(/^(\d+)\.(\d+)(?:\.(\d+))?$/);
	return m ? { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3] ?? 0) } : null;
}

/**
 * The NVDA versions an add-on declares in its repository, shaped like a
 * store entry, for add-ons that are not in the store yet.
 */
export function entryFromBuildVars(addon) {
	const minNVDAVersion = toApiVersion(addon.minimumNVDA);
	const lastTestedVersion = toApiVersion(addon.lastTestedNVDA);
	return minNVDAVersion && lastTestedVersion ? { minNVDAVersion, lastTestedVersion } : null;
}

/** Versions of an add-on published in the store, oldest first. */
export async function storeVersions(gh, addonName) {
	const files = await gh.get(`/repos/${STORE}/contents/addons/${encodeURIComponent(addonName)}`);
	if (!Array.isArray(files)) return [];
	return files
		.filter((f) => f.name.endsWith(".json"))
		.map((f) => f.name.slice(0, -".json".length))
		.sort(compareVersions);
}

/** The store's record of one published version, or null. */
export async function storeEntry(gh, addonName, version) {
	const text = await gh.raw(`/repos/${STORE}/contents/addons/${encodeURIComponent(addonName)}/${version}.json`);
	return text ? JSON.parse(text) : null;
}

/** VirusTotal result recorded by the store: {malicious, suspicious} or null. */
export function scanVerdict(entry) {
	const stats = entry?.scanResults?.virusTotal?.[0]?.last_analysis_stats;
	if (!stats) return null;
	return { malicious: stats.malicious || 0, suspicious: stats.suspicious || 0 };
}

/** NVDA API versions known to the store. */
export async function nvdaVersions(gh) {
	const text = await gh.raw(`/repos/${STORE}/contents/transform/nvdaAPIVersions.json`);
	return text ? JSON.parse(text) : [];
}

/** The newest NVDA version the store treats as stable. */
export function latestStableNvda(versions) {
	const stable = versions.filter((v) => !v.experimental);
	stable.sort((a, b) => compareApiVersions(a.apiVer, b.apiVer));
	return stable[stable.length - 1] ?? null;
}

/**
 * NVDA's rule: an add-on works with an NVDA release when the release is not
 * older than the add-on's minimum, and the add-on was last tested on at
 * least the release's backwards-compatibility version.
 */
export function isCompatible(entry, nvda) {
	if (!entry || !nvda) return null;
	const minimumOk = compareApiVersions(entry.minNVDAVersion, nvda.apiVer) <= 0;
	const testedOk = compareApiVersions(entry.lastTestedVersion, nvda.backCompatTo) >= 0;
	return minimumOk && testedOk;
}

/** Open submission issues in the store that point at this repository. */
export async function openSubmissions(gh, org, repo) {
	const q = encodeURIComponent(`repo:${STORE} is:issue is:open "github.com/${org}/${repo}/releases" in:body`);
	const result = await gh.get(`/search/issues?q=${q}&per_page=10`);
	return (result?.items ?? []).map((i) => ({ number: i.number, url: i.html_url, title: i.title }));
}

/** Everything the bot reports about one add-on. */
export async function addonStatus(gh, org, addon, nvda) {
	const release = await gh.get(`/repos/${org}/${addon.repo}/releases/latest`);
	const latest = release?.tag_name ? release.tag_name.replace(/^v/, "") : null;
	const versions = await storeVersions(gh, addon.name);
	const storeLatest = versions[versions.length - 1] ?? null;
	const entry = storeLatest ? await storeEntry(gh, addon.name, storeLatest) : null;
	const pending = await openSubmissions(gh, org, addon.repo);
	return {
		addon,
		latest,
		storeLatest,
		verdict: scanVerdict(entry),
		compatible: isCompatible(entry, nvda),
		lastTested: entry?.lastTestedVersion ?? null,
		pending,
		nvda,
	};
}

/** One add-on's status as a Telegram message section (HTML). */
export function formatAddonStatus(s) {
	const lines = [`<b>${escapeHtml(s.addon.summary)}</b> (${escapeHtml(s.addon.repo)})`];
	lines.push(`• Rilis terbaru: ${s.latest ? escapeHtml(s.latest) : "belum ada rilis"}`);
	lines.push(`• Di Add-on Store: ${s.storeLatest ? escapeHtml(s.storeLatest) : "belum ada"}`);
	for (const p of s.pending) {
		lines.push(`• ⏳ Submit menunggu NV Access: <a href="${p.url}">#${p.number}</a>`);
	}
	const behind = s.latest && (!s.storeLatest || compareVersions(s.latest, s.storeLatest) > 0);
	if (behind && s.pending.length === 0) {
		lines.push(`• 📝 Versi ${escapeHtml(s.latest)} belum disubmit. Submit sendiri lewat <a href="${SUBMIT_FORM}">formulir Add-on Store</a>.`);
	}
	if (s.verdict) {
		const flagged = s.verdict.malicious + s.verdict.suspicious;
		lines.push(
			flagged === 0
				? "• 🛡️ VirusTotal: bersih"
				: `• ⚠️ VirusTotal: ${s.verdict.malicious} berbahaya, ${s.verdict.suspicious} mencurigakan`,
		);
	}
	if (s.compatible !== null && s.nvda) {
		const nvdaName = escapeHtml(s.nvda.description);
		lines.push(
			s.compatible
				? `• ✅ Kompatibel dengan ${nvdaName}`
				: `• ❌ Tidak kompatibel dengan ${nvdaName}: terakhir dites di NVDA ${formatApiVersion(s.lastTested)}, minimal ${formatApiVersion(s.nvda.backCompatTo)}`,
		);
	}
	return lines.join("\n");
}
