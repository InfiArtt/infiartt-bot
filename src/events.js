/**
 * Turns organization webhook events into Telegram messages. Only the
 * important ones produce a message; everything else returns null.
 * CI results are deliberately ignored: members' failed runs would flood the
 * group.
 */
import { escapeHtml, truncate } from "./util.js";

const SERIOUS = new Set(["critical", "high"]);
const SEVERITY = { critical: "KRITIS", high: "TINGGI" };

function repoLink(repo) {
	return `<a href="${repo.html_url}">${escapeHtml(repo.full_name ?? repo.name)}</a>`;
}

function by(payload) {
	return payload.sender?.login ? ` oleh ${escapeHtml(payload.sender.login)}` : "";
}

function repositoryEvent(p) {
	const repo = p.repository;
	const visibility = repo.private ? "privat" : "publik";
	switch (p.action) {
		case "created":
			return `🆕 Repo baru (${visibility}): ${repoLink(repo)}${by(p)}`;
		case "deleted":
			return `🗑️ Repo dihapus: <b>${escapeHtml(repo.full_name)}</b>${by(p)}`;
		case "publicized":
			return `🌍 Repo ${repoLink(repo)} sekarang <b>publik</b>${by(p)}`;
		case "privatized":
			return `🔒 Repo ${repoLink(repo)} sekarang <b>privat</b>${by(p)}`;
		case "archived":
			return `🗄️ Repo ${repoLink(repo)} diarsipkan${by(p)}`;
		case "unarchived":
			return `📂 Repo ${repoLink(repo)} tidak diarsipkan lagi${by(p)}`;
		case "renamed":
			return `✏️ Repo diganti nama: ${escapeHtml(p.changes?.repository?.name?.from ?? "?")} → ${repoLink(repo)}${by(p)}`;
		case "transferred":
			return `📦 Repo ${repoLink(repo)} dipindahkan${by(p)}`;
		default:
			return null;
	}
}

function organizationEvent(p) {
	const member = escapeHtml(p.membership?.user?.login ?? p.invitation?.login ?? p.invitation?.email ?? "?");
	switch (p.action) {
		case "member_added":
			return `👋 Anggota baru di InfiArtt: <b>${member}</b>`;
		case "member_removed":
			return `🚪 <b>${member}</b> keluar dari InfiArtt`;
		case "member_invited":
			return `✉️ <b>${member}</b> diundang ke InfiArtt${by(p)}`;
		default:
			return null;
	}
}

function secretScanningEvent(p) {
	if (p.action !== "created") return null;
	const alert = p.alert;
	const kind = escapeHtml(alert.secret_type_display_name ?? alert.secret_type ?? "rahasia");
	const where = repoLink(p.repository);
	if (alert.push_protection_bypassed) {
		const who = escapeHtml(alert.push_protection_bypassed_by?.login ?? "seseorang");
		return `⚠️ <b>Push protection dilewati</b> oleh ${who}: ${kind} tetap di-push ke ${where}.\nGanti kuncinya, lalu tandai peringatannya: ${alert.html_url}`;
	}
	return `🔐 <b>Rahasia terdeteksi</b> di ${where}: ${kind}.\nSegera ganti (revoke) kuncinya, karena repo publik bisa dibaca siapa saja.\n${alert.html_url}`;
}

function dependabotEvent(p) {
	if (p.action !== "created") return null;
	const alert = p.alert;
	const severity = alert.security_advisory?.severity ?? alert.security_vulnerability?.severity;
	if (!SERIOUS.has(severity)) return null;
	const pkg = alert.dependency?.package ?? alert.security_vulnerability?.package ?? {};
	const summary = truncate(alert.security_advisory?.summary ?? "", 200);
	return (
		`🧩 <b>Library rentan (${SEVERITY[severity]})</b> di ${repoLink(p.repository)}: ` +
		`${escapeHtml(pkg.name ?? "?")} (${escapeHtml(pkg.ecosystem ?? "?")})` +
		(summary ? `\n${escapeHtml(summary)}` : "") +
		`\n${alert.html_url}`
	);
}

/**
 * Returns the message for an event, or null to stay quiet.
 * `isAddonRepo(name)` tells whether a repository builds an NVDA add-on.
 */
export async function messageForEvent(event, payload, { isAddonRepo } = {}) {
	switch (event) {
		case "ping":
			return "🔗 Webhook GitHub InfiArtt tersambung. Info penting akan dikirim ke grup ini.";
		case "repository":
			return repositoryEvent(payload);
		case "organization":
			return organizationEvent(payload);
		case "secret_scanning_alert":
			return secretScanningEvent(payload);
		case "dependabot_alert":
			return dependabotEvent(payload);
		case "release": {
			if (payload.action !== "published" || payload.release?.draft) return null;
			if (!isAddonRepo || !(await isAddonRepo(payload.repository.name))) return null;
			const r = payload.release;
			return (
				`🚀 Add-on ${repoLink(payload.repository)} merilis <b>${escapeHtml(r.tag_name)}</b>` +
				(r.prerelease ? " (pre-release)" : "") +
				`.\nJangan lupa submit sendiri ke Add-on Store NVDA lewat formulirnya; bot tidak menyubmit apa pun.\n${r.html_url}`
			);
		}
		default:
			return null;
	}
}
