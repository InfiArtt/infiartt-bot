/**
 * Runs every 30 minutes and reports what changed in the NV Access Add-on
 * Store during exactly the last 30 minutes, so nothing is reported twice
 * and the bot needs no storage. Read-only: it never writes to the store.
 */
import {
	STORE,
	findAddonRepos,
	isCompatible,
	latestStableNvda,
	nvdaVersions,
	scanVerdict,
	storeEntry,
	storeVersions,
} from "./addons.js";
import { escapeHtml, formatApiVersion, truncate } from "./util.js";

export const INTERVAL_MS = 30 * 60 * 1000;

function inWindow(iso, since, until) {
	const t = Date.parse(iso);
	return t >= since.getTime() && t < until.getTime();
}

function verdictText(entry) {
	const v = scanVerdict(entry);
	if (!v) return "";
	const flagged = v.malicious + v.suspicious;
	return flagged === 0 ? " VirusTotal: bersih 🛡️" : ` ⚠️ VirusTotal: ${v.malicious} berbahaya, ${v.suspicious} mencurigakan.`;
}

/** Returns the messages to send for the window ending at `scheduledTime`. */
export async function collectStoreNews(gh, org, scheduledTime) {
	const until = new Date(scheduledTime);
	const since = new Date(scheduledTime - INTERVAL_MS);
	const range = `since=${since.toISOString()}&until=${until.toISOString()}`;
	const messages = [];
	const addons = await findAddonRepos(gh, org);

	// 1. A new version of one of our add-ons was merged into the store.
	for (const addon of addons) {
		const commits = await gh.get(`/repos/${STORE}/commits?path=addons/${encodeURIComponent(addon.name)}&${range}`);
		if (!commits?.length) continue;
		const versions = await storeVersions(gh, addon.name);
		const latest = versions[versions.length - 1];
		const entry = latest ? await storeEntry(gh, addon.name, latest) : null;
		messages.push(`✅ <b>${escapeHtml(addon.summary)} ${escapeHtml(latest ?? "")}</b> sudah tayang di Add-on Store NVDA.${verdictText(entry)}`);
	}

	// 2. Someone (NV Access staff or their bot) commented on one of our submissions.
	const q = encodeURIComponent(`repo:${STORE} is:issue "github.com/${org}/" in:body updated:>=${since.toISOString()}`);
	const issues = (await gh.get(`/search/issues?q=${q}&per_page=20`))?.items ?? [];
	for (const issue of issues) {
		const comments = (await gh.get(`${issue.comments_url}?since=${since.toISOString()}&per_page=50`)) ?? [];
		for (const c of comments) {
			if (!inWindow(c.created_at, since, until)) continue;
			const text = truncate(String(c.body ?? "").split("\n---")[0], 400);
			messages.push(
				`💬 Komentar baru dari <b>${escapeHtml(c.user?.login ?? "?")}</b> di submit <a href="${issue.html_url}">#${issue.number}</a> (${escapeHtml(issue.title)}):\n<blockquote>${escapeHtml(text)}</blockquote>\nBalas sendiri di GitHub jika perlu; jangan lewat bot atau AI.`,
			);
		}
		if (issue.closed_at && inWindow(issue.closed_at, since, until)) {
			messages.push(`📕 Submit <a href="${issue.html_url}">#${issue.number}</a> ditutup (${escapeHtml(issue.title)}).`);
		}
	}

	// 3. NV Access changed the list of NVDA versions: check compatibility.
	const nvdaChanges = await gh.get(`/repos/${STORE}/commits?path=transform/nvdaAPIVersions.json&${range}`);
	if (nvdaChanges?.length) {
		const nvda = latestStableNvda(await nvdaVersions(gh));
		if (nvda) {
			messages.push(`🆕 Daftar versi NVDA di Add-on Store diperbarui. Versi stabil terbaru: <b>${escapeHtml(nvda.description)}</b>.`);
			for (const addon of addons) {
				const versions = await storeVersions(gh, addon.name);
				const latest = versions[versions.length - 1];
				const entry = latest ? await storeEntry(gh, addon.name, latest) : null;
				if (entry && isCompatible(entry, nvda) === false) {
					messages.push(
						`❌ <b>${escapeHtml(addon.summary)} ${escapeHtml(latest)}</b> tidak kompatibel dengan ${escapeHtml(nvda.description)}: ` +
							`terakhir dites di NVDA ${formatApiVersion(entry.lastTestedVersion)}, minimal ${formatApiVersion(nvda.backCompatTo)}. ` +
							"Rilis versi baru dengan lastTestedNVDAVersion yang lebih baru.",
					);
				}
			}
		}
	}

	return messages;
}
