/** Telegram side: sending messages and answering commands in the group. */
import { addonStatus, findAddonRepos, formatAddonStatus, latestStableNvda, nvdaVersions } from "./addons.js";
import { escapeHtml } from "./util.js";

const LIMIT = 4000; // Telegram allows 4096 characters per message.

/** Sends HTML text to a chat, split into several messages when long. */
export async function sendMessage(env, text, { chatId = env.TELEGRAM_CHAT_ID, fetchImpl = fetch } = {}) {
	const chunks = [];
	let current = "";
	for (const part of String(text).split("\n\n")) {
		if (current && (current + "\n\n" + part).length > LIMIT) {
			chunks.push(current);
			current = part;
		} else {
			current = current ? `${current}\n\n${part}` : part;
		}
	}
	if (current) chunks.push(current);
	for (const chunk of chunks) {
		const res = await fetchImpl(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ chat_id: chatId, text: chunk, parse_mode: "HTML", disable_web_page_preview: true }),
		});
		if (!res.ok) throw new Error(`Telegram sendMessage failed: ${res.status}`);
	}
}

/** Entries of ALLOWED_USERS: Telegram user IDs and/or @usernames. */
export function allowedUsers(env) {
	return String(env.ALLOWED_USERS ?? env.ALLOWED_USER_IDS ?? "")
		.split(/[\s,]+/)
		.filter(Boolean)
		.map((entry) => entry.replace(/^@/, "").toLowerCase());
}

/**
 * Whether this sender may use commands. With no ALLOWED_USERS, everyone in
 * the configured group may: the commands only read data, and the group's
 * membership is already controlled by its admins. Usernames can change, so
 * a numeric ID is the stricter choice when the group grows.
 */
export function isAllowed(env, from) {
	const allowed = allowedUsers(env);
	if (allowed.length === 0) return true;
	const id = String(from?.id ?? "");
	const username = String(from?.username ?? "").toLowerCase();
	return allowed.includes(id) || (username !== "" && allowed.includes(username));
}

const HELP = [
	"🤖 <b>Bot InfiArtt</b>",
	"",
	"/addons: status semua add-on NVDA (versi, Add-on Store, VirusTotal, kompatibilitas)",
	"/status: ringkasan keamanan dan perlindungan repo",
	"/bantuan: pesan ini",
	"",
	"Bot juga otomatis mengabari info penting: peringatan keamanan, perubahan repo dan anggota, dan kabar dari Add-on Store NVDA.",
].join("\n");

async function addonsReport(gh, org) {
	const [addons, versions] = await Promise.all([findAddonRepos(gh, org), nvdaVersions(gh)]);
	if (addons.length === 0) return "Belum ada repo add-on NVDA di InfiArtt.";
	const nvda = latestStableNvda(versions);
	const sections = [];
	for (const addon of addons) {
		sections.push(formatAddonStatus(await addonStatus(gh, org, addon, nvda)));
	}
	return `🛒 <b>Add-on NVDA InfiArtt</b>\n\n${sections.join("\n\n")}`;
}

async function statusReport(gh, org) {
	const [secrets, vulns, repos] = await Promise.all([
		gh.all(`/orgs/${org}/secret-scanning/alerts?state=open`, 2),
		gh.all(`/orgs/${org}/dependabot/alerts?state=open&severity=critical,high`, 2),
		gh.all(`/orgs/${org}/repos?type=public`),
	]);
	const active = repos.filter((r) => !r.archived);
	let protectedCount = 0;
	for (const repo of active) {
		const rules = await gh.get(`/repos/${org}/${repo.name}/rulesets`);
		if ((rules ?? []).some((r) => r.name === "Protect default branch" && r.enforcement === "active")) protectedCount++;
	}
	return [
		"📊 <b>Status InfiArtt</b>",
		`🔐 Rahasia bocor yang belum ditangani: ${secrets.length}`,
		`🧩 Library rentan (tinggi/kritis): ${vulns.length}`,
		`🛡️ Repo publik dengan branch utama terlindungi: ${protectedCount}/${active.length}`,
	].join("\n");
}

/**
 * Handles one Telegram update. Commands are answered only in the configured
 * group and only for allowed users; /id is the exception while setting up.
 */
export async function handleUpdate(update, env, { gh, fetchImpl = fetch } = {}) {
	const msg = update?.message;
	if (!msg?.text || !msg.text.startsWith("/")) return;
	const command = msg.text.trim().split(/\s+/)[0].split("@")[0].toLowerCase();
	const reply = (text) => sendMessage(env, text, { chatId: msg.chat.id, fetchImpl });
	const inGroup = String(msg.chat.id) === String(env.TELEGRAM_CHAT_ID ?? "");
	const allowed = isAllowed(env, msg.from);

	if (command === "/id") {
		// Lets the owners find the IDs during setup; silent once configured elsewhere.
		if (env.TELEGRAM_CHAT_ID && !inGroup) return;
		await reply(`ID chat ini: <code>${escapeHtml(msg.chat.id)}</code>\nID Telegram kamu: <code>${escapeHtml(msg.from?.id)}</code>`);
		return;
	}
	if (!inGroup || !allowed) return;

	const org = env.GITHUB_ORG;
	try {
		switch (command) {
			case "/start":
			case "/bantuan":
			case "/help":
				await reply(HELP);
				break;
			case "/addons":
				await reply("⏳ Mengecek add-on...");
				await reply(await addonsReport(gh, org));
				break;
			case "/status":
				await reply(await statusReport(gh, org));
				break;
			default:
				await reply("Perintah tidak dikenal. Ketik /bantuan.");
		}
	} catch (error) {
		console.error("command failed", command, error);
		// Name the failing request, so a problem can be traced from the group.
		const where = error.path ? ` (${escapeHtml(error.path)}: ${error.status})` : "";
		await reply(`❌ Maaf, gagal mengambil data dari GitHub${where}. Coba lagi sebentar lagi.`);
	}
}
