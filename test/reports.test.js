import assert from "node:assert/strict";
import { test } from "node:test";

import { makeGitHub } from "../src/github.js";
import { jobsAt, runScheduled } from "../src/index.js";
import {
	ago,
	DAY_MS,
	nvdaReport,
	prReport,
	releasesReport,
	repoReport,
	securityReport,
	teamsReport,
	tokenReminders,
	weeklyDigest,
} from "../src/reports.js";
import { COMMANDS, handleUpdate } from "../src/telegram.js";
import { fakeFetch, orgRoutes, storeEntryJson } from "./fakes.js";

const NOW = Date.parse("2026-10-05T01:00:00Z"); // a Monday, 08:00 WIB
const daysAgo = (n) => new Date(NOW - n * DAY_MS).toISOString();
const gh = (routes) => makeGitHub("t", fakeFetch(routes).fetchImpl);

const VULN = (repo, pkg, severity) => ({
	repository: { name: repo },
	dependency: { package: { name: pkg, ecosystem: "npm" } },
	security_advisory: { severity },
});

test("ago() speaks Indonesian", () => {
	assert.equal(ago(new Date(NOW - 20 * 1000).toISOString(), NOW), "baru saja");
	assert.equal(ago(new Date(NOW - 5 * 60000).toISOString(), NOW), "5 menit lalu");
	assert.equal(ago(daysAgo(0.5), NOW), "12 jam lalu");
	assert.equal(ago(daysAgo(3), NOW), "3 hari lalu");
	assert.equal(ago(daysAgo(70), NOW), "2 bulan lalu");
	assert.equal(ago(daysAgo(800), NOW), "2 tahun lalu");
});

test("/keamanan groups vulnerable packages per repository, worst first", async () => {
	const text = await securityReport(gh([
		[/^\/orgs\/InfiArtt\/secret-scanning\/alerts/, [{ number: 4, repository: { name: "web" }, secret_type_display_name: "Slack Token", html_url: "https://s/4" }]],
		[/^\/orgs\/InfiArtt\/dependabot\/alerts/, [
			VULN("InfiArttWeb", "js-yaml", "high"), VULN("InfiArttWeb", "js-yaml", "high"),
			VULN("InfiArttWeb", "astro", "high"), VULN("InfiArttWeb", "astro", "critical"),
		]],
	]), "InfiArtt");
	assert.match(text, /Rahasia bocor \(1\).*web: Slack Token/s);
	assert.match(text, /Library rentan tinggi\/kritis \(4\)/);
	assert.match(text, /InfiArttWeb<\/a>: astro ×2 \(KRITIS\), js-yaml ×2 \(tinggi\)/);
});

test("/keamanan says so when everything is clean", async () => {
	const text = await securityReport(gh([[/alerts/, []]]), "InfiArtt");
	assert.match(text, /Tidak ada rahasia bocor/);
});

test("/repo lists repositories newest first, splitting issues from PRs", async () => {
	const text = await repoReport(gh([
		[/^\/orgs\/InfiArtt\/repos/, [
			{ name: "old", html_url: "https://g/old", pushed_at: daysAgo(40), open_issues_count: 0, private: false },
			{ name: "accessify-play", html_url: "https://g/a", pushed_at: daysAgo(1), open_issues_count: 5, private: false },
			{ name: "InfiArttWeb", html_url: "https://g/w", pushed_at: daysAgo(3), open_issues_count: 0, private: true },
			{ name: "gone", archived: true, pushed_at: daysAgo(1) },
		]],
		[/^\/search\/issues/, { items: [{ repository_url: "https://api.github.com/repos/InfiArtt/accessify-play" }, { repository_url: "https://api.github.com/repos/InfiArtt/accessify-play" }] }],
		["/repos/InfiArtt/accessify-play/rulesets", [{ name: "Protect default branch", enforcement: "active" }]],
		["/repos/InfiArtt/old/rulesets", []],
	]), "InfiArtt", NOW);
	assert.match(text, /Repo InfiArtt \(3\)/, "archived repositories are left out");
	assert.ok(text.indexOf("accessify-play") < text.indexOf("InfiArttWeb") && text.indexOf("InfiArttWeb") < text.indexOf(">old<"));
	assert.match(text, /accessify-play<\/a> 🛡️\n   update 1 hari lalu · 3 issue · 2 PR/);
	assert.match(text, /InfiArttWeb<\/a> 🔒\n/, "private repositories show no protection status");
	assert.match(text, /old<\/a> ⚠️ belum terlindungi/);
});

test("/pr lists open pull requests, oldest first", async () => {
	const { fetchImpl, calls } = fakeFetch([
		[/^\/search\/issues/, { total_count: 2, items: [
			{ number: 7, title: "Fix the volume dialog", html_url: "https://p/7", repository_url: "https://api.github.com/repos/InfiArtt/accessify-play", user: { login: "fz0308" }, created_at: daysAgo(6) },
			{ number: 2, title: "Draft", html_url: "https://p/2", repository_url: "https://api.github.com/repos/InfiArtt/hariku", user: { login: "x" }, created_at: daysAgo(1), draft: true },
		] }],
	]);
	const text = await prReport(makeGitHub("t", fetchImpl), "InfiArtt", NOW);
	assert.match(calls[0], /sort=created&order=asc/);
	assert.match(text, /PR terbuka \(2\)/);
	assert.match(text, /accessify-play#7<\/a> Fix the volume dialog\n   oleh fz0308 · dibuka 6 hari lalu/);
	assert.match(text, /hariku#2.*· draft/s);
	assert.match(await prReport(gh([[/^\/search\/issues/, { total_count: 0, items: [] }]]), "InfiArtt", NOW), /Tidak ada PR/);
});

test("/rilis shows each repository's latest release, newest first", async () => {
	const text = await releasesReport(gh([
		[/^\/orgs\/InfiArtt\/repos/, [{ name: "accessify-play" }, { name: "hariku-core" }, { name: "TeamTalkBot" }]],
		["/repos/InfiArtt/accessify-play/releases/latest", { tag_name: "v1.12.1", html_url: "https://r/a", published_at: daysAgo(3) }],
		["/repos/InfiArtt/hariku-core/releases/latest", { tag_name: "v2.3.0", html_url: "https://r/h", published_at: daysAgo(1), prerelease: true }],
		["/repos/InfiArtt/TeamTalkBot/releases/latest", 404],
	]), "InfiArtt", NOW);
	assert.match(text, /hariku-core: <a href="https:\/\/r\/h">v2\.3\.0<\/a> \(pre-release\) · 1 hari lalu\n• accessify-play: .*v1\.12\.1.* · 3 hari lalu/);
	assert.doesNotMatch(text, /TeamTalkBot/);
});

test("/nvda shows stable and upcoming NVDA, and add-on compatibility even before the store", async () => {
	const text = await nvdaReport(gh(orgRoutes([["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", 404]])), "InfiArtt");
	assert.match(text, /Stabil terbaru: <b>NVDA 2026\.1<\/b>, add-on harus dites minimal di NVDA 2026\.1/);
	assert.match(text, /Belum final: NVDA 2026\.3, minimal 2026\.1/);
	assert.match(text, /Accessify Play 1\.12\.1 \(belum di toko, menurut buildVars\): 2026\.1 ✅, 2026\.3 ✅/);
});

test("/nvda uses the store's record once the add-on is published", async () => {
	const text = await nvdaReport(gh(orgRoutes([
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay/1.12.1.json", storeEntryJson({ lastTested: { major: 2025, minor: 3, patch: 0 } })],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", [{ name: "1.12.1.json" }]],
	])), "InfiArtt");
	assert.match(text, /Accessify Play 1\.12\.1: 2026\.1 ❌/);
});

test("/tim lists teams with their members and repositories", async () => {
	const text = await teamsReport(gh([
		[/^\/orgs\/InfiArtt\/teams\/aegis\/members/, [{ login: "raf-li" }, { login: "rexya2017" }]],
		[/^\/orgs\/InfiArtt\/teams\/aegis\/repos/, [{ name: "accessify-play", role_name: "maintain" }]],
		[/^\/orgs\/InfiArtt\/teams/, [{ name: "Aegis", slug: "aegis" }]],
	]), "InfiArtt");
	assert.match(text, /<b>Aegis<\/b>\n• Anggota: raf-li, rexya2017\n• Repo: accessify-play \(maintain\)/);
});

test("/tim explains a missing token permission instead of failing", async () => {
	const fetchImpl = async () => new Response("{}", { status: 403 });
	const text = await teamsReport(makeGitHub("t", fetchImpl), "InfiArtt");
	assert.match(text, /Members: Read-only/);
});

test("every command in the menu answers", async () => {
	const names = COMMANDS.map((c) => c.name);
	assert.deepEqual(names, ["addons", "status", "keamanan", "repo", "pr", "rilis", "nvda", "tim", "bantuan"]);
	const { fetchImpl, sent } = fakeFetch([[/./, []]]);
	const env = { GITHUB_ORG: "InfiArtt", TELEGRAM_CHAT_ID: "1", TELEGRAM_BOT_TOKEN: "b" };
	for (const name of names) {
		sent.length = 0;
		await handleUpdate({ message: { text: `/${name}`, chat: { id: 1 }, from: { id: 9 } } }, env, { gh: makeGitHub("t", fetchImpl), fetchImpl });
		assert.ok(sent.length > 0, `/${name} answered`);
	}
});

// ------------------------------------------------------------------ automatic jobs
test("the daily and weekly jobs run at fixed times within the 30-minute cron", () => {
	assert.deepEqual(jobsAt(Date.parse("2026-10-05T01:00:00Z")), { storeNews: true, tokenReminders: false, weeklyDigest: true });
	assert.deepEqual(jobsAt(Date.parse("2026-10-05T01:30:00Z")), { storeNews: true, tokenReminders: false, weeklyDigest: false });
	assert.deepEqual(jobsAt(Date.parse("2026-10-06T01:00:00Z")), { storeNews: true, tokenReminders: false, weeklyDigest: false }, "Tuesday: no digest");
	assert.deepEqual(jobsAt(Date.parse("2026-10-06T02:00:00Z")), { storeNews: true, tokenReminders: true, weeklyDigest: false });
});

function tokenFetch(expiry, routes = []) {
	const { fetchImpl: base, sent } = fakeFetch(routes);
	const fetchImpl = async (url, init) => {
		if (url.endsWith("/rate_limit")) return new Response("{}", { headers: expiry ? { "github-authentication-token-expiration": expiry } : {} });
		return base(url, init);
	};
	return { fetchImpl, sent };
}

test("token reminders come at 30, 14, 7, 3, 1 and 0 days, not every day", async () => {
	const at = (days) => new Date(NOW + days * DAY_MS + 3600 * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
	const remind = async (days) => tokenReminders(makeGitHub("t", tokenFetch(at(days), [[/^\/search\/issues/, { items: [] }]]).fetchImpl), "InfiArtt", NOW);
	assert.match((await remind(14))[0], /GH_READ_TOKEN\) kedaluwarsa dalam 14 hari/);
	assert.equal((await remind(13)).length, 0);
	assert.match((await remind(0))[0], /kedaluwarsa hari ini/);
	assert.equal((await tokenReminders(makeGitHub("t", tokenFetch(null, [[/^\/search\/issues/, { items: [] }]]).fetchImpl), "InfiArtt", NOW)).length, 0, "a token without expiry needs no reminder");
});

test("the admin token reminder issue from InfiArtt/.github is relayed once", async () => {
	const issue = (created) => [[/^\/search\/issues/, { items: [{ number: 3, html_url: "https://i/3", created_at: created }] }]];
	const fresh = await tokenReminders(makeGitHub("t", tokenFetch(null, issue(daysAgo(0.2))).fetchImpl), "InfiArtt", NOW);
	assert.match(fresh[0], /ORG_ADMIN_TOKEN.*issue #3/);
	const old = await tokenReminders(makeGitHub("t", tokenFetch(null, issue(daysAgo(2))).fetchImpl), "InfiArtt", NOW);
	assert.equal(old.length, 0);
});

test("the weekly digest summarises the past 7 days", async () => {
	const counts = { "is:issue created": 4, "is:pr created": 3, "is:merged": 2, "is:pr is:open": 1 };
	const { fetchImpl } = tokenFetch("2027-10-03 03:55:09 UTC", orgRoutes([
		[/^\/search\/issues/, (path) => {
			const q = decodeURIComponent(path);
			const key = Object.keys(counts).find((k) => q.includes(k));
			return { total_count: key ? counts[key] : 0, items: [] };
		}],
		[/^\/orgs\/InfiArtt\/secret-scanning\/alerts/, []],
		[/^\/orgs\/InfiArtt\/dependabot\/alerts/, [VULN("InfiArttWeb", "astro", "critical")]],
		["/repos/InfiArtt/accessify-play/releases/latest", { tag_name: "v1.12.1" }],
		[/^\/repos\/InfiArtt\/accessify-play\/releases/, [{ tag_name: "v1.12.1", html_url: "https://r/1121", published_at: daysAgo(3) }, { tag_name: "v1.11.1", published_at: daysAgo(30) }]],
		[/^\/repos\/InfiArtt\/TeamTalkBot\/releases/, []],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", 404],
	]));
	const text = await weeklyDigest(makeGitHub("t", fetchImpl), "InfiArtt", NOW);
	assert.match(text, /Ringkasan mingguan InfiArtt/);
	assert.match(text, /Issue baru: 4/);
	assert.match(text, /PR baru: 3, di-merge: 2, masih terbuka: 1/);
	assert.match(text, /Rilis: accessify-play <a href="https:\/\/r\/1121">v1\.12\.1<\/a>$/m, "only this week's releases");
	assert.match(text, /library rentan \(tinggi\/kritis\): 1/);
	assert.match(text, /Accessify Play: rilis 1\.12\.1, toko belum ada/);
	assert.match(text, /Token bot berlaku 363 hari lagi/);
});

test("a busy week lists 8 releases and counts the rest", async () => {
	const many = Array.from({ length: 11 }, (_, i) => ({ tag_name: `v1.${i}.0`, html_url: `https://r/${i}`, published_at: daysAgo(1) }));
	const { fetchImpl } = tokenFetch(null, orgRoutes([
		[/^\/search\/issues/, { total_count: 0, items: [] }],
		[/alerts/, []],
		["/repos/InfiArtt/accessify-play/releases/latest", { tag_name: "v1.10.0" }],
		[/^\/repos\/InfiArtt\/accessify-play\/releases/, many],
		[/^\/repos\/InfiArtt\/TeamTalkBot\/releases/, []],
		["/repos/nvaccess/addon-datastore/contents/addons/AccessifyPlay", 404],
	]));
	const text = await weeklyDigest(makeGitHub("t", fetchImpl), "InfiArtt", NOW);
	assert.match(text, /v1\.7\.0<\/a> \+3 lainnya \(\/rilis\)/);
	assert.doesNotMatch(text, /v1\.8\.0/);
});

test("Monday 08:00 WIB sends the digest to the group", async () => {
	const { fetchImpl, sent } = tokenFetch(null, orgRoutes([[/./, []]]));
	const realFetch = globalThis.fetch;
	globalThis.fetch = fetchImpl;
	try {
		await runScheduled({ GITHUB_ORG: "InfiArtt", TELEGRAM_CHAT_ID: "-1", TELEGRAM_BOT_TOKEN: "b" }, NOW, makeGitHub("t", fetchImpl));
	} finally {
		globalThis.fetch = realFetch;
	}
	assert.ok(sent.some((m) => /Ringkasan mingguan/.test(m.text)));
});
