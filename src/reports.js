/**
 * The text of every report the bot can send: answers to commands, the
 * weekly digest and the token reminders. All read-only.
 */
import {
	addonStatus,
	entryFromBuildVars,
	findAddonRepos,
	formatAddonStatus,
	isCompatible,
	latestStableNvda,
	nvdaVersions,
	storeEntry,
	storeVersions,
} from "./addons.js";
import { compareApiVersions, escapeHtml, formatApiVersion, truncate } from "./util.js";

export const DAY_MS = 24 * 60 * 60 * 1000;
const SEVERITY = { critical: "KRITIS", high: "tinggi" };
const RULESET = "Protect default branch";

/** "3 hari lalu" and friends. */
export function ago(iso, now = Date.now()) {
	const minutes = Math.floor((now - Date.parse(iso)) / 60000);
	if (minutes < 1) return "baru saja";
	if (minutes < 60) return `${minutes} menit lalu`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours} jam lalu`;
	const days = Math.floor(hours / 24);
	if (days < 30) return `${days} hari lalu`;
	if (days < 365) return `${Math.floor(days / 30)} bulan lalu`;
	return `${Math.floor(days / 365)} tahun lalu`;
}

function link(url, text) {
	return `<a href="${url}">${escapeHtml(text)}</a>`;
}

function repoName(searchItem) {
	return searchItem.repository_url.split("/").pop();
}

async function searchCount(gh, query) {
	const result = await gh.get(`/search/issues?q=${encodeURIComponent(query)}&per_page=1`);
	return result?.total_count ?? 0;
}

async function isProtected(gh, org, repo) {
	const rules = await gh.get(`/repos/${org}/${repo}/rulesets`);
	return (rules ?? []).some((r) => r.name === RULESET && r.enforcement === "active");
}

async function securityAlerts(gh, org) {
	const [secrets, vulns] = await Promise.all([
		gh.all(`/orgs/${org}/secret-scanning/alerts?state=open`, 3),
		gh.all(`/orgs/${org}/dependabot/alerts?state=open&severity=critical,high`, 3),
	]);
	return { secrets, vulns };
}

// ------------------------------------------------------------------ commands

export async function addonsReport(gh, org) {
	const [addons, versions] = await Promise.all([findAddonRepos(gh, org), nvdaVersions(gh)]);
	if (addons.length === 0) return "Belum ada repo add-on NVDA di InfiArtt.";
	const nvda = latestStableNvda(versions);
	const sections = [];
	for (const addon of addons) {
		sections.push(formatAddonStatus(await addonStatus(gh, org, addon, nvda)));
	}
	return `🛒 <b>Add-on NVDA InfiArtt</b>\n\n${sections.join("\n\n")}`;
}

export async function statusReport(gh, org) {
	const [{ secrets, vulns }, repos] = await Promise.all([securityAlerts(gh, org), gh.all(`/orgs/${org}/repos?type=public`)]);
	const active = repos.filter((r) => !r.archived);
	let protectedCount = 0;
	for (const repo of active) {
		if (await isProtected(gh, org, repo.name)) protectedCount++;
	}
	return [
		"📊 <b>Status InfiArtt</b>",
		`🔐 Rahasia bocor yang belum ditangani: ${secrets.length}`,
		`🧩 Library rentan (tinggi/kritis): ${vulns.length}`,
		`🛡️ Repo publik dengan branch utama terlindungi: ${protectedCount}/${active.length}`,
		"",
		"Rincian: /keamanan",
	].join("\n");
}

export async function securityReport(gh, org) {
	const { secrets, vulns } = await securityAlerts(gh, org);
	const lines = ["🛡️ <b>Keamanan InfiArtt</b>"];
	if (secrets.length === 0 && vulns.length === 0) {
		lines.push("Tidak ada rahasia bocor atau library rentan (tinggi/kritis) yang terbuka. 👍");
		return lines.join("\n");
	}
	if (secrets.length) {
		lines.push("", `🔐 <b>Rahasia bocor (${secrets.length})</b>`);
		for (const a of secrets) {
			lines.push(`• ${escapeHtml(a.repository?.name)}: ${escapeHtml(a.secret_type_display_name ?? a.secret_type)} (${link(a.html_url, `#${a.number}`)})`);
		}
		lines.push("Ganti (revoke) kuncinya dulu, baru tutup peringatannya.");
	}
	if (vulns.length) {
		// repo -> package -> {count, critical}
		const byRepo = new Map();
		for (const a of vulns) {
			const repo = a.repository?.name ?? "?";
			const pkg = a.dependency?.package?.name ?? "?";
			const packages = byRepo.get(repo) ?? new Map();
			const entry = packages.get(pkg) ?? { count: 0, critical: false };
			entry.count++;
			entry.critical ||= a.security_advisory?.severity === "critical";
			packages.set(pkg, entry);
			byRepo.set(repo, packages);
		}
		lines.push("", `🧩 <b>Library rentan tinggi/kritis (${vulns.length})</b>`);
		for (const [repo, packages] of byRepo) {
			const parts = [...packages]
				.sort(([, a], [, b]) => Number(b.critical) - Number(a.critical) || b.count - a.count)
				.map(([name, e]) => `${escapeHtml(name)}${e.count > 1 ? ` ×${e.count}` : ""} (${e.critical ? SEVERITY.critical : SEVERITY.high})`);
			lines.push(`• ${link(`https://github.com/${org}/${repo}/security/dependabot`, repo)}: ${parts.join(", ")}`);
		}
		lines.push("Biasanya cukup perbarui dependensinya; peringatannya tertutup sendiri.");
	}
	return lines.join("\n");
}

export async function repoReport(gh, org, now = Date.now()) {
	const repos = (await gh.all(`/orgs/${org}/repos?type=all`)).filter((r) => !r.archived);
	repos.sort((a, b) => Date.parse(b.pushed_at) - Date.parse(a.pushed_at));
	const openPrs = (await gh.get(`/search/issues?q=${encodeURIComponent(`org:${org} is:pr is:open`)}&per_page=100`))?.items ?? [];
	const prCount = new Map();
	for (const pr of openPrs) prCount.set(repoName(pr), (prCount.get(repoName(pr)) ?? 0) + 1);

	const lines = [`📁 <b>Repo InfiArtt (${repos.length})</b>`];
	for (const repo of repos) {
		const prs = prCount.get(repo.name) ?? 0;
		const issues = Math.max(0, (repo.open_issues_count ?? 0) - prs); // GitHub counts PRs as issues too
		let guard = "";
		if (!repo.private) {
			try {
				guard = (await isProtected(gh, org, repo.name)) ? " 🛡️" : " ⚠️ belum terlindungi";
			} catch {
				guard = "";
			}
		}
		lines.push(`• ${link(repo.html_url, repo.name)}${repo.private ? " 🔒" : ""}${guard}\n   update ${ago(repo.pushed_at, now)} · ${issues} issue · ${prs} PR`);
	}
	lines.push("", "🛡️ branch utama terlindungi · 🔒 privat");
	return lines.join("\n");
}

export async function prReport(gh, org, now = Date.now()) {
	const query = encodeURIComponent(`org:${org} is:pr is:open`);
	const result = await gh.get(`/search/issues?q=${query}&sort=created&order=asc&per_page=30`);
	const prs = result?.items ?? [];
	if (prs.length === 0) return "🔀 Tidak ada PR yang terbuka. 👍";
	const lines = [`🔀 <b>PR terbuka (${result.total_count})</b>, yang paling lama menunggu di atas`];
	for (const pr of prs) {
		lines.push(
			`• ${link(pr.html_url, `${repoName(pr)}#${pr.number}`)} ${escapeHtml(truncate(pr.title, 80))}\n` +
				`   oleh ${escapeHtml(pr.user?.login ?? "?")} · dibuka ${ago(pr.created_at, now)}${pr.draft ? " · draft" : ""}`,
		);
	}
	return lines.join("\n");
}

export async function releasesReport(gh, org, now = Date.now()) {
	const repos = (await gh.all(`/orgs/${org}/repos?type=all`)).filter((r) => !r.archived);
	const rows = [];
	for (const repo of repos) {
		const release = await gh.get(`/repos/${org}/${repo.name}/releases/latest`);
		if (release) rows.push({ repo: repo.name, release });
	}
	if (rows.length === 0) return "📦 Belum ada repo yang punya rilis.";
	rows.sort((a, b) => Date.parse(b.release.published_at) - Date.parse(a.release.published_at));
	return [
		"📦 <b>Rilis terbaru</b>",
		...rows.map(({ repo, release }) =>
			`• ${escapeHtml(repo)}: ${link(release.html_url, release.tag_name)}${release.prerelease ? " (pre-release)" : ""} · ${ago(release.published_at, now)}`,
		),
	].join("\n");
}

export async function nvdaReport(gh, org) {
	const versions = [...(await nvdaVersions(gh))].sort((a, b) => compareApiVersions(a.apiVer, b.apiVer));
	const stable = latestStableNvda(versions);
	if (!stable) return "Tidak bisa membaca daftar versi NVDA dari Add-on Store.";
	const upcoming = versions.filter((v) => v.experimental && compareApiVersions(v.apiVer, stable.apiVer) > 0);
	const lines = [
		"🗣️ <b>Versi NVDA di Add-on Store</b>",
		`• Stabil terbaru: <b>${escapeHtml(stable.description)}</b>, add-on harus dites minimal di NVDA ${formatApiVersion(stable.backCompatTo)}`,
		...upcoming.map((v) => `• Belum final: ${escapeHtml(v.description)}, minimal ${formatApiVersion(v.backCompatTo)}`),
	];
	const addons = await findAddonRepos(gh, org);
	if (addons.length) {
		lines.push("", "<b>Kompatibilitas add-on</b>");
		for (const addon of addons) {
			const published = await storeVersions(gh, addon.name);
			const latest = published[published.length - 1];
			const entry = latest ? await storeEntry(gh, addon.name, latest) : entryFromBuildVars(addon);
			const label = latest ? `${addon.summary} ${latest}` : `${addon.summary} ${addon.version ?? ""} (belum di toko, menurut buildVars)`;
			if (!entry) {
				lines.push(`• ${escapeHtml(label)}: data versi NVDA tidak ditemukan`);
				continue;
			}
			const marks = [stable, ...upcoming].map((v) => `${escapeHtml(v.description.replace(/^NVDA /, ""))} ${isCompatible(entry, v) ? "✅" : "❌"}`);
			lines.push(`• ${escapeHtml(label.trim())}: ${marks.join(", ")}`);
		}
	}
	return lines.join("\n");
}

export async function teamsReport(gh, org) {
	let teams;
	try {
		teams = await gh.all(`/orgs/${org}/teams`);
	} catch (error) {
		if (error.status === 403) {
			return "🔑 Token bot belum boleh membaca tim. Tambahkan izin <b>Members: Read-only</b> (bagian Organization permissions) di token GH_READ_TOKEN.";
		}
		throw error;
	}
	if (teams.length === 0) return "👥 Belum ada tim (atau token bot belum punya izin Members: Read-only).";
	const lines = ["👥 <b>Tim InfiArtt</b>"];
	for (const team of teams) {
		const [members, repos] = await Promise.all([
			gh.all(`/orgs/${org}/teams/${team.slug}/members`),
			gh.all(`/orgs/${org}/teams/${team.slug}/repos`),
		]);
		lines.push(
			"",
			`<b>${escapeHtml(team.name)}</b>`,
			`• Anggota: ${members.map((m) => escapeHtml(m.login)).join(", ") || "-"}`,
			`• Repo: ${repos.map((r) => `${escapeHtml(r.name)} (${escapeHtml(r.role_name ?? "?")})`).join(", ") || "-"}`,
		);
	}
	return lines.join("\n");
}

// ------------------------------------------------------------------ automatic

/** At most 8 releases, then "+N lainnya", so a busy week stays one readable line. */
function formatReleases(releases, max = 8) {
	if (releases.length === 0) return "tidak ada";
	const shown = releases.slice(0, max).join(", ");
	return releases.length > max ? `${shown} +${releases.length - max} lainnya (/rilis)` : shown;
}

/** Monday's summary of the past 7 days. */
export async function weeklyDigest(gh, org, now = Date.now()) {
	const since = new Date(now - 7 * DAY_MS).toISOString().slice(0, 10);
	const [newIssues, newPrs, merged, openPrs, { secrets, vulns }, repos, addons, nvdaList, expiry] = await Promise.all([
		searchCount(gh, `org:${org} is:issue created:>=${since}`),
		searchCount(gh, `org:${org} is:pr created:>=${since}`),
		searchCount(gh, `org:${org} is:pr is:merged merged:>=${since}`),
		searchCount(gh, `org:${org} is:pr is:open`),
		securityAlerts(gh, org),
		gh.all(`/orgs/${org}/repos?type=all`),
		findAddonRepos(gh, org),
		nvdaVersions(gh),
		gh.tokenExpiry(),
	]);

	const releases = [];
	for (const repo of repos.filter((r) => !r.archived)) {
		const list = (await gh.get(`/repos/${org}/${repo.name}/releases?per_page=10`)) ?? [];
		for (const r of list) {
			if (!r.draft && Date.parse(r.published_at) >= now - 7 * DAY_MS) releases.push(`${escapeHtml(repo.name)} ${link(r.html_url, r.tag_name)}`);
		}
	}

	const nvda = latestStableNvda(nvdaList);
	const addonLines = [];
	for (const addon of addons) {
		const s = await addonStatus(gh, org, addon, nvda);
		const pending = s.pending.length ? `, ⏳ submit #${s.pending[0].number} menunggu` : "";
		const compat = s.compatible === false ? ", ❌ tidak kompatibel dengan NVDA terbaru" : "";
		addonLines.push(`• ${escapeHtml(addon.summary)}: rilis ${escapeHtml(s.latest ?? "-")}, toko ${escapeHtml(s.storeLatest ?? "belum ada")}${pending}${compat}`);
	}

	const lines = [
		"🗓️ <b>Ringkasan mingguan InfiArtt</b> (7 hari terakhir)",
		"",
		`🐛 Issue baru: ${newIssues}`,
		`🔀 PR baru: ${newPrs}, di-merge: ${merged}, masih terbuka: ${openPrs}`,
		`📦 Rilis: ${formatReleases(releases)}`,
		`🛡️ Rahasia bocor: ${secrets.length}, library rentan (tinggi/kritis): ${vulns.length}`,
	];
	if (addonLines.length) lines.push("", "🛒 <b>Add-on NVDA</b>", ...addonLines);
	if (expiry) lines.push("", `🔑 Token bot berlaku ${Math.floor((Date.parse(expiry) - now) / DAY_MS)} hari lagi.`);
	lines.push("", "Perintah: /bantuan");
	return lines.join("\n");
}

/** Days before expiry on which the bot's own token is mentioned. */
const REMIND_AT = new Set([30, 14, 7, 3, 1, 0]);

/** Reminders about tokens running out, checked once a day. */
export async function tokenReminders(gh, org, now = Date.now()) {
	const messages = [];
	const expiry = await gh.tokenExpiry();
	if (expiry) {
		const days = Math.floor((Date.parse(expiry) - now) / DAY_MS);
		if (REMIND_AT.has(days) || days < 0) {
			const when = days < 0 ? "sudah kedaluwarsa" : days === 0 ? "kedaluwarsa hari ini" : `kedaluwarsa dalam ${days} hari`;
			messages.push(
				`🔑 Token GitHub bot (GH_READ_TOKEN) ${when}. Buat token baru dengan izin yang sama, lalu ganti secret GH_READ_TOKEN di repo infiartt-bot.`,
			);
		}
	}
	// The protect-new-repositories workflow in InfiArtt/.github opens this issue 14 days ahead.
	const q = encodeURIComponent(`repo:${org}/.github is:issue is:open "ORG_ADMIN_TOKEN expires soon" in:title`);
	for (const issue of (await gh.get(`/search/issues?q=${q}`))?.items ?? []) {
		if (now - Date.parse(issue.created_at) < DAY_MS) {
			messages.push(`🔑 Token admin (ORG_ADMIN_TOKEN) segera kedaluwarsa. Detail: ${link(issue.html_url, `issue #${issue.number}`)}`);
		}
	}
	return messages;
}
