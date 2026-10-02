/** Telegram side: sending messages and answering commands in the group. */
import {
	addonsReport,
	nvdaReport,
	prReport,
	releasesReport,
	repoReport,
	securityReport,
	statusReport,
	teamsReport,
} from "./reports.js";
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

/** Commands, in the order /bantuan and Telegram's menu list them. */
export const COMMANDS = [
	{ name: "addons", description: "Status add-on NVDA: versi, Add-on Store, VirusTotal, kompatibilitas", run: addonsReport, slow: true },
	{ name: "status", description: "Ringkasan keamanan dan perlindungan repo", run: statusReport },
	{ name: "keamanan", description: "Rincian rahasia bocor dan library rentan per repo", run: securityReport },
	{ name: "repo", description: "Semua repo: update terakhir, issue, PR, perlindungan", run: repoReport, slow: true },
	{ name: "pr", description: "PR yang terbuka dan sudah berapa lama menunggu", run: prReport },
	{ name: "rilis", description: "Rilis terbaru tiap repo", run: releasesReport, slow: true },
	{ name: "nvda", description: "Versi NVDA terbaru dan kompatibilitas add-on", run: nvdaReport },
	{ name: "tim", description: "Tim, anggotanya, dan repo yang mereka pegang", run: teamsReport },
	{ name: "bantuan", description: "Daftar perintah" },
];

const HELP = [
	"🤖 <b>Bot InfiArtt</b>",
	"",
	...COMMANDS.map((c) => `/${c.name}: ${c.description}`),
	"",
	"Otomatis: info keamanan dan perubahan repo/anggota secara langsung, kabar Add-on Store NVDA tiap 30 menit, ringkasan mingguan tiap Senin pagi, dan pengingat sebelum token kedaluwarsa.",
].join("\n");

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
	const name = command.slice(1);
	try {
		if (["start", "bantuan", "help"].includes(name)) {
			await reply(HELP);
			return;
		}
		const entry = COMMANDS.find((c) => c.name === name && c.run);
		if (!entry) {
			await reply("Perintah tidak dikenal. Ketik /bantuan.");
			return;
		}
		if (entry.slow) await reply("⏳ Sebentar, sedang mengecek...");
		await reply(await entry.run(gh, org));
	} catch (error) {
		console.error("command failed", command, error);
		// Name the failing request, so a problem can be traced from the group.
		const where = error.path ? ` (${escapeHtml(error.path)}: ${error.status})` : "";
		await reply(`❌ Maaf, gagal mengambil data dari GitHub${where}. Coba lagi sebentar lagi.`);
	}
}
