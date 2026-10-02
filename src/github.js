/** A minimal, read-only GitHub REST client. */

const API = "https://api.github.com";

/** The rel="next" URL from a Link header, or null. */
export function nextLink(header) {
	const m = String(header ?? "").match(/<([^>]+)>;\s*rel="next"/);
	return m ? m[1] : null;
}

/** An error that says which GitHub request failed, without exposing the token. */
export class GitHubError extends Error {
	constructor(path, status) {
		super(`GitHub GET ${path} failed: ${status}`);
		this.path = path;
		this.status = status;
	}
}

export function makeGitHub(token, fetchImpl = fetch) {
	async function send(path, raw) {
		const url = path.startsWith("http") ? path : API + path;
		const res = await fetchImpl(url, {
			headers: {
				Authorization: `Bearer ${token}`,
				Accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json",
				"User-Agent": "infiartt-bot",
				"X-GitHub-Api-Version": "2022-11-28",
			},
		});
		if (res.status !== 404 && !res.ok) throw new GitHubError(url.replace(API, "").split("?")[0], res.status);
		return res;
	}

	async function request(path, { raw = false } = {}) {
		const res = await send(path, raw);
		if (res.status === 404) return null;
		return raw ? res.text() : res.json();
	}

	return {
		/** Parsed JSON, or null when the resource does not exist. */
		get: (path) => request(path),
		/** File contents as text, or null when the file does not exist. */
		raw: (path) => request(path, { raw: true }),
		/**
		 * Every item of a list endpoint, up to `maxPages` pages. Follows the
		 * Link header rather than numbering pages: some endpoints, such as an
		 * organization's Dependabot alerts, reject the `page` parameter.
		 */
		async all(path, maxPages = 5) {
			const items = [];
			let url = `${path}${path.includes("?") ? "&" : "?"}per_page=100`;
			for (let page = 0; url && page < maxPages; page++) {
				const res = await send(url, false);
				if (res.status === 404) break;
				const batch = await res.json();
				if (!Array.isArray(batch)) break;
				items.push(...batch);
				url = nextLink(res.headers.get("Link"));
			}
			return items;
		},
	};
}
