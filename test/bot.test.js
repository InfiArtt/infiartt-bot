import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";

import { addonStatus, findAddonRepos, formatAddonStatus, isCompatible, latestStableNvda } from "../src/addons.js";
import { messageForEvent } from "../src/events.js";
import { makeGitHub, nextLink } from "../src/github.js";
import worker, { verifyGitHubSignature } from "../src/index.js";
import { collectStoreNews, INTERVAL_MS } from "../src/scheduled.js";
import { handleUpdate } from "../src/telegram.js";
import { compareVersions, escapeHtml, parseVersion, safeEqual } from "../src/util.js";
import { fakeFetch, NVDA_VERSIONS, orgRoutes, storeEntryJson } from "./fakes.js";

const ENV = {
	GITHUB_ORG: "InfiArtt",
	TELEGRAM_BOT_TOKEN: "bot-token",
	TELEGRAM_WEBHOOK_SECRET: "tg-secret",
	GITHUB_WEBHOOK_SECRET: "gh-secret",
	GH_READ_TOKEN: "read-token",
	TELEGRAM_CHAT_ID: "-100123",
	ALLOWED_USERS: "11, @Rexya",
};

// ------------------------------------------------------------------ util
test("versions parse and sort", () => {
	assert.deepEqual(parseVersion("v1.12.1"), [1, 12, 1]);
	assert.deepEqual(parseVersion("1.9"), [1, 9, 0]);
	assert.equal(parseVersion("latest"), null);
	assert.deepEqual(["1.10.0", "1.9.2", "1.12.1"].sort(compareVersions), ["1.9.2", "1.10.0", "1.12.1"]);
});

test("HTML is escaped and secrets compare safely", () => {
	assert.equal(escapeHtml("<b>&</b>"), "&lt;b&gt;&amp;&lt;/b&gt;");
	assert.ok(safeEqual("abc", "abc"));
	assert.ok(!safeEqual("abc", "abd"));
	assert.ok(!safeEqual("abc", "abcd"));
});

// ------------------------------------------------------------------ GitHub webhook signature
test("GitHub signatures are verified", async () => {
	const body = '{"zen":"hi"}';
	const good = "sha256=" + createHmac("sha256", "gh-secret").update(body).digest("hex");
	assert.ok(await verifyGitHubSignature("gh-secret", body, good));
	assert.ok(!(await verifyGitHubSignature("other", body, good)));
	assert.ok(!(await verifyGitHubSignature("gh-secret", body + " ", good)));
	assert.ok(!(await verifyGitHubSignature("gh-secret", body, undefined)));
});

function ctx() {
	const pending = [];
	return { waitUntil: (p) => pending.push(p), done: () => Promise.all(pending) };
}

test("the Worker rejects unsigned GitHub deliveries and wrong Telegram secrets", async () => {
	const res1 = await worker.fetch(new Request("https://bot.example/github", { method: "POST", body: "{}", headers: { "X-GitHub-Event": "ping" } }), ENV, ctx());
	assert.equal(res1.status, 401);
	const res2 = await worker.fetch(new Request("https://bot.example/telegram", { method: "POST", body: "{}", headers: { "X-Telegram-Bot-Api-Secret-Token": "wrong" } }), ENV, ctx());
	assert.equal(res2.status, 403);
	const res3 = await worker.fetch(new Request("https://bot.example/"), ENV, ctx());
	assert.equal(res3.status, 200);
});

test("a signed ping reaches the Telegram group", async () => {
	const { fetchImpl, sent } = fakeFetch(orgRoutes());
	const realFetch = globalThis.fetch;
	globalThis.fetch = fetchImpl;
	try {
		const body = JSON.stringify({ zen: "hi" });
		const sig = "sha256=" + createHmac("sha256", "gh-secret").update(body).digest("hex");
		const c = ctx();
		const res = await worker.fetch(new Request("https://bot.example/github", { method: "POST", body, headers: { "X-GitHub-Event": "ping", "X-Hub-Signature-256": sig } }), ENV, c);
		assert.equal(res.status, 202);
		await c.done();
		assert.equal(sent.length, 1);
		assert.equal(sent[0].chat_id, "-100123");
		assert.match(sent[0].text, /Webhook GitHub InfiArtt tersambung/);
	} finally {
		globalThis.fetch = realFetch;
	}
});

// ------------------------------------------------------------------ events
const repo = { name: "hariku", full_name: "InfiArtt/hariku", html_url: "https://github.com/InfiArtt/hariku", private: false };

test("important organization events become Indonesian messages", async () => {
	assert.match(await messageForEvent("repository", { action: "created", repository: repo, sender: { login: "aswar999" } }), /Repo baru \(publik\).*oleh aswar999/);
	assert.match(await messageForEvent("repository", { action: "deleted", repository: repo }), /Repo dihapus/);
	assert.match(await messageForEvent("repository", { action: "publicized", repository: repo }), /sekarang <b>publik<\/b>/);
	assert.match(await messageForEvent("organization", { action: "member_added", membership: { user: { login: "fz0308" } } }), /Anggota baru.*fz0308/);
	assert.match(await messageForEvent("organization", { action: "member_removed", membership: { user: { login: "x" } } }), /keluar dari InfiArtt/);
});

test("security alerts are reported, minor ones are not", async () => {
	const secret = await messageForEvent("secret_scanning_alert", {
		action: "created", repository: repo, alert: { secret_type_display_name: "Google API Key", html_url: "https://alert" },
	});
	assert.match(secret, /Rahasia terdeteksi.*Google API Key/s);
	const bypass = await messageForEvent("secret_scanning_alert", {
		action: "created", repository: repo,
		alert: { secret_type_display_name: "Token", html_url: "https://a", push_protection_bypassed: true, push_protection_bypassed_by: { login: "m" } },
	});
	assert.match(bypass, /Push protection dilewati.*oleh m/s);
	const vuln = (severity) => messageForEvent("dependabot_alert", {
		action: "created", repository: repo,
		alert: { html_url: "https://d", dependency: { package: { name: "requests", ecosystem: "pip" } }, security_advisory: { severity, summary: "Bad thing" } },
	});
	assert.match(await vuln("critical"), /Library rentan \(KRITIS\).*requests \(pip\)/s);
	assert.match(await vuln("high"), /TINGGI/);
	assert.equal(await vuln("moderate"), null);
	assert.equal(await vuln("low"), null);
});

test("CI results and other noise stay quiet", async () => {
	assert.equal(await messageForEvent("workflow_run", { action: "completed", workflow_run: { conclusion: "failure" } }), null);
	assert.equal(await messageForEvent("push", {}), null);
	assert.equal(await messageForEvent("issues", { action: "opened" }), null);
});

test("an add-on release reminds to submit by hand, other releases are ignored", async () => {
	const payload = (name) => ({ action: "published", repository: { ...repo, name, full_name: `InfiArtt/${name}` }, release: { tag_name: "v1.13.0", html_url: "https://rel" } });
	const isAddonRepo = async (name) => name === "accessify-play";
	const msg = await messageForEvent("release", payload("accessify-play"), { isAddonRepo });
	assert.match(msg, /merilis <b>v1\.13\.0<\/b>/);
	assert.match(msg, /submit sendiri/);
	assert.doesNotMatch(msg, /issues\/new/, "the bot never links a prefilled submission");
	assert.equal(await messageForEvent("release", payload("hariku-core"), { isAddonRepo }), null);
});

// ------------------------------------------------------------------ add-ons
test("add-on repos are found from buildVars.py", async () => {
	const { fetchImpl } = fakeFetch(orgRoutes());
	const addons = await findAddonRepos(makeGitHub("t", fetchImpl), "InfiArtt");
	assert.deepEqual(addons, [{ repo: "accessify-play", name: "AccessifyPlay", summary: "Accessify Play", version: "1.12.1", minimumNVDA: "2025.1", lastTestedNVDA: "2026.1" }]);
});

test("compatibility follows NVDA's rule", () => {
	const nvda = latestStableNvda(NVDA_VERSIONS);
	assert.equal(nvda.description, "NVDA 2026.1", "experimental versions are skipped");
	const entry = (lastTested) => ({ minNVDAVersion: { major: 2025, minor: 1 }, lastTestedVersion: lastTested });
	assert.equal(isCompatible(entry({ major: 2026, minor: 1, patch: 0 }), nvda), true);
	assert.equal(isCompatible(entry({ major: 2025, minor: 3, patch: 0 }), nvda), false);
	assert.equal(isCompatible(null, nvda), null);
});

test("an add-on's status covers versions, pending submissions, VirusTotal and compatibility", async () => {
	const { fetchImpl } = fakeFetch(orgRoutes([
		["/repos/InfiArtt/accessify-play/releases/latest", { tag_name: "v1.12.1" }],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay/1.12.0.json", storeEntryJson({ suspicious: 1 })],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", [{ name: "1.11.1.json" }, { name: "1.12.0.json" }]],
		[/^\/search\/issues/, { items: [{ number: 11924, html_url: "https://github.com/nvaccess/addon-datastore/issues/11924", title: "[Submit add-on]: Accessify Play 1.12.1" }] }],
	]));
	const gh = makeGitHub("t", fetchImpl);
	const nvda = latestStableNvda(NVDA_VERSIONS);
	const s = await addonStatus(gh, "InfiArtt", { repo: "accessify-play", name: "AccessifyPlay", summary: "Accessify Play" }, nvda);
	assert.equal(s.latest, "1.12.1");
	assert.equal(s.storeLatest, "1.12.0");
	const text = formatAddonStatus(s);
	assert.match(text, /Rilis terbaru: 1\.12\.1/);
	assert.match(text, /Di Add-on Store: 1\.12\.0/);
	assert.match(text, /Submit menunggu NV Access.*#11924/);
	assert.doesNotMatch(text, /belum disubmit/, "no reminder while a submission is pending");
	assert.match(text, /VirusTotal: 0 berbahaya, 1 mencurigakan/);
	assert.match(text, /Kompatibel dengan NVDA 2026\.1/);
});

test("a release that is not in the store and not submitted gets a reminder", () => {
	const text = formatAddonStatus({
		addon: { repo: "accessify-play", summary: "Accessify Play" }, latest: "1.13.0", storeLatest: "1.12.1",
		pending: [], verdict: null, compatible: false, lastTested: { major: 2025, minor: 3 }, nvda: latestStableNvda(NVDA_VERSIONS),
	});
	assert.match(text, /Versi 1\.13\.0 belum disubmit/);
	assert.match(text, /Tidak kompatibel dengan NVDA 2026\.1: terakhir dites di NVDA 2025\.3, minimal 2026\.1/);
});

// ------------------------------------------------------------------ Telegram commands
function update(text, { chat = -100123, from = 11, username } = {}) {
	return { message: { text, chat: { id: chat }, from: { id: from, username } } };
}

test("commands answer only in the group and only for allowed users", async () => {
	const { fetchImpl, sent } = fakeFetch(orgRoutes());
	const gh = makeGitHub("t", fetchImpl);
	await handleUpdate(update("/bantuan", { from: 99 }), ENV, { gh, fetchImpl });
	await handleUpdate(update("/bantuan", { chat: 555 }), ENV, { gh, fetchImpl });
	assert.equal(sent.length, 0);
	await handleUpdate(update("/bantuan@InfiArttBot"), ENV, { gh, fetchImpl });
	assert.equal(sent.length, 1);
	assert.match(sent[0].text, /\/addons/);
});

test("users are allowed by ID or by @username, and everyone in the group when no list is set", async () => {
	const { fetchImpl, sent } = fakeFetch([]);
	const gh = makeGitHub("t", fetchImpl);
	await handleUpdate(update("/bantuan", { from: 44, username: "rexya" }), ENV, { gh, fetchImpl });
	assert.equal(sent.length, 1, "username matches case-insensitively, with or without @");
	await handleUpdate(update("/bantuan", { from: 55, username: "stranger" }), ENV, { gh, fetchImpl });
	assert.equal(sent.length, 1, "someone not on the list is ignored");
	await handleUpdate(update("/bantuan", { from: 55, username: "stranger" }), { ...ENV, ALLOWED_USERS: "" }, { gh, fetchImpl });
	assert.equal(sent.length, 2, "no list: every member of the group may use commands");
	await handleUpdate(update("/bantuan", { chat: 777, from: 55 }), { ...ENV, ALLOWED_USERS: "" }, { gh, fetchImpl });
	assert.equal(sent.length, 2, "but never outside the configured group");
});

test("/id helps during setup but stays quiet elsewhere once configured", async () => {
	const { fetchImpl, sent } = fakeFetch([]);
	const gh = makeGitHub("t", fetchImpl);
	await handleUpdate(update("/id", { chat: -100999, from: 33 }), { ...ENV, TELEGRAM_CHAT_ID: "" }, { gh, fetchImpl });
	assert.match(sent[0].text, /-100999.*33/s);
	await handleUpdate(update("/id", { chat: -100999, from: 33 }), ENV, { gh, fetchImpl });
	assert.equal(sent.length, 1, "no answer outside the configured group");
});

test("/status summarises security and protection", async () => {
	const { fetchImpl, sent } = fakeFetch([
		[/^\/orgs\/InfiArtt\/secret-scanning\/alerts/, []],
		[/^\/orgs\/InfiArtt\/dependabot\/alerts/, [{ number: 1 }]],
		[/^\/orgs\/InfiArtt\/repos/, [{ name: "a", archived: false }, { name: "b", archived: false }, { name: "old", archived: true }]],
		["/repos/InfiArtt/a/rulesets", [{ name: "Protect default branch", enforcement: "active" }]],
		["/repos/InfiArtt/b/rulesets", []],
	]);
	await handleUpdate(update("/status"), ENV, { gh: makeGitHub("t", fetchImpl), fetchImpl });
	assert.match(sent[0].text, /Rahasia bocor yang belum ditangani: 0/);
	assert.match(sent[0].text, /Library rentan \(tinggi\/kritis\): 1/);
	assert.match(sent[0].text, /terlindungi: 1\/2/);
});

test("a GitHub failure gives a friendly message instead of silence", async () => {
	const { fetchImpl, sent } = fakeFetch([[/^\/orgs\//, () => { throw new Error("boom"); }]]);
	await handleUpdate(update("/status"), ENV, { gh: makeGitHub("t", fetchImpl), fetchImpl });
	assert.match(sent[0].text, /gagal mengambil data/);
});

test("a failed GitHub request is named in the message", async () => {
	const fetchImpl = async (url, init) => {
		if (url.startsWith("https://api.telegram.org/")) { fetchImpl.sent.push(JSON.parse(init.body).text); return new Response("{}"); }
		return new Response("{}", { status: 403 });
	};
	fetchImpl.sent = [];
	await handleUpdate(update("/status"), ENV, { gh: makeGitHub("t", fetchImpl), fetchImpl });
	assert.match(fetchImpl.sent[0], /gagal mengambil data dari GitHub \(\/orgs\/InfiArtt\/[a-z-]+\/alerts|repos: 403\)/);
	assert.doesNotMatch(fetchImpl.sent[0], /per_page|token/, "no query string or secrets in the message");
});

test("lists follow the Link header, never the page parameter", async () => {
	assert.equal(nextLink('<https://api.github.com/x?after=abc>; rel="next", <https://api.github.com/x?before=z>; rel="prev"'), "https://api.github.com/x?after=abc");
	assert.equal(nextLink(null), null);
	const seen = [];
	const fetchImpl = async (url) => {
		seen.push(url);
		if (/[?&]page=/.test(url)) return new Response('{"message":"Pagination using the page parameter is not supported."}', { status: 400 });
		if (url.includes("after=2")) return new Response(JSON.stringify([{ n: 3 }]));
		return new Response(JSON.stringify([{ n: 1 }, { n: 2 }]), { headers: { Link: '<https://api.github.com/orgs/InfiArtt/dependabot/alerts?per_page=100&after=2>; rel="next"' } });
	};
	const items = await makeGitHub("t", fetchImpl).all("/orgs/InfiArtt/dependabot/alerts?state=open");
	assert.deepEqual(items.map((i) => i.n), [1, 2, 3]);
	assert.equal(seen.length, 2);
	assert.ok(seen.every((u) => !/[?&]page=/.test(u)));
});

// ------------------------------------------------------------------ scheduled store news
test("store news reports exactly the last 30 minutes", async () => {
	const now = Date.parse("2026-10-02T06:00:00Z");
	const inside = new Date(now - 10 * 60 * 1000).toISOString();
	const before = new Date(now - INTERVAL_MS - 60 * 1000).toISOString();
	const { fetchImpl, calls } = fakeFetch(orgRoutes([
		[/^\/repos\/nvaccess\/addon-datastore\/commits\?path=addons\/AccessifyPlay/, [{ sha: "abc" }]],
		[/^\/repos\/nvaccess\/addon-datastore\/commits\?path=transform/, []],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay/1.12.1.json", storeEntryJson()],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", [{ name: "1.12.1.json" }]],
		[/^\/search\/issues/, { items: [{ number: 11924, html_url: "https://i/11924", title: "[Submit add-on]: Accessify Play 1.12.1", comments_url: "https://api.github.com/repos/nvaccess/addon-datastore/issues/11924/comments", closed_at: inside }] }],
		[/^\/repos\/nvaccess\/addon-datastore\/issues\/11924\/comments/, [
			{ created_at: before, user: { login: "github-actions[bot]" }, body: "Welcome" },
			{ created_at: inside, user: { login: "seanbudd" }, body: "Approved, thanks!\n---\nfooter" },
		]],
	]));
	const messages = await collectStoreNews(makeGitHub("t", fetchImpl), "InfiArtt", now);
	const window = calls.find((u) => u.includes("commits?path=addons"));
	assert.match(window, /since=2026-10-02T05:30:00\.000Z&until=2026-10-02T06:00:00\.000Z/);
	assert.ok(messages.some((m) => /Accessify Play 1\.12\.1<\/b> sudah tayang.*bersih/.test(m)));
	assert.ok(messages.some((m) => /seanbudd.*Approved, thanks!/s.test(m)));
	assert.ok(!messages.some((m) => /Welcome/.test(m)), "older comments are not repeated");
	assert.ok(!messages.some((m) => /footer/.test(m)), "the bot footer is cut");
	assert.ok(messages.some((m) => /ditutup/.test(m)));
});

test("a new NVDA release warns about add-ons that become incompatible", async () => {
	const now = Date.parse("2026-10-02T06:00:00Z");
	const versions = [...NVDA_VERSIONS, { description: "NVDA 2027.1", apiVer: { major: 2027, minor: 1, patch: 0 }, backCompatTo: { major: 2027, minor: 1, patch: 0 } }];
	const { fetchImpl } = fakeFetch([
		["/repos/nvaccess/addon-datastore/contents/transform/nvdaAPIVersions.json", JSON.stringify(versions)],
		[/^\/repos\/nvaccess\/addon-datastore\/commits\?path=transform/, [{ sha: "x" }]],
		[/^\/repos\/nvaccess\/addon-datastore\/commits\?path=addons/, []],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay/1.12.1.json", storeEntryJson()],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", [{ name: "1.12.1.json" }]],
		[/^\/search\/issues/, { items: [] }],
		...orgRoutes(),
	]);
	const messages = await collectStoreNews(makeGitHub("t", fetchImpl), "InfiArtt", now);
	assert.ok(messages.some((m) => /Versi stabil terbaru: <b>NVDA 2027\.1/.test(m)));
	assert.ok(messages.some((m) => /Accessify Play 1\.12\.1<\/b> tidak kompatibel dengan NVDA 2027\.1/.test(m)));
});
