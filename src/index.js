/**
 * InfiArtt bot: a Cloudflare Worker that
 *  - receives organization webhooks from GitHub (POST /github) and forwards
 *    the important ones to the team's Telegram group,
 *  - answers commands in that group (POST /telegram, Telegram webhook),
 *  - every 30 minutes, reports news about our NVDA add-ons in the Add-on Store.
 *
 * Secrets: TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET, GITHUB_WEBHOOK_SECRET,
 * GH_READ_TOKEN (read-only), TELEGRAM_CHAT_ID, and optionally ALLOWED_USERS.
 * Variable: GITHUB_ORG.
 */
import { findAddonRepos } from "./addons.js";
import { messageForEvent } from "./events.js";
import { makeGitHub } from "./github.js";
import { collectStoreNews } from "./scheduled.js";
import { handleUpdate, sendMessage } from "./telegram.js";
import { safeEqual } from "./util.js";

/** Checks GitHub's X-Hub-Signature-256 header against the raw body. */
export async function verifyGitHubSignature(secret, body, header) {
	if (!secret || !header?.startsWith("sha256=")) return false;
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
	const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return safeEqual(`sha256=${hex}`, header);
}

export async function handleGitHubDelivery(event, payload, env, gh) {
	const isAddonRepo = async (name) => (await findAddonRepos(gh, env.GITHUB_ORG)).some((a) => a.repo === name);
	const text = await messageForEvent(event, payload, { isAddonRepo });
	if (text) await sendMessage(env, text);
}

export async function runScheduled(env, scheduledTime, gh) {
	const messages = await collectStoreNews(gh, env.GITHUB_ORG, scheduledTime);
	for (const text of messages) await sendMessage(env, text);
}

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const gh = makeGitHub(env.GH_READ_TOKEN);

		if (request.method === "POST" && url.pathname === "/telegram") {
			const token = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
			if (!env.TELEGRAM_WEBHOOK_SECRET || !safeEqual(token, env.TELEGRAM_WEBHOOK_SECRET)) {
				return new Response("forbidden", { status: 403 });
			}
			const update = await request.json();
			ctx.waitUntil(handleUpdate(update, env, { gh }).catch((e) => console.error("telegram", e)));
			return new Response("ok");
		}

		if (request.method === "POST" && url.pathname === "/github") {
			const body = await request.text();
			const ok = await verifyGitHubSignature(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("X-Hub-Signature-256"));
			if (!ok) return new Response("bad signature", { status: 401 });
			const event = request.headers.get("X-GitHub-Event");
			ctx.waitUntil(handleGitHubDelivery(event, JSON.parse(body), env, gh).catch((e) => console.error("github", event, e)));
			return new Response("accepted", { status: 202 });
		}

		if (request.method === "GET" && url.pathname === "/") {
			return new Response("InfiArtt bot is running.");
		}
		return new Response("not found", { status: 404 });
	},

	async scheduled(event, env, ctx) {
		const gh = makeGitHub(env.GH_READ_TOKEN);
		ctx.waitUntil(runScheduled(env, event.scheduledTime, gh).catch((e) => console.error("scheduled", e)));
	},
};
