/** A minimal, read-only GitHub REST client. */

const API = "https://api.github.com";

export function makeGitHub(token, fetchImpl = fetch) {
	async function request(path, { raw = false } = {}) {
		const url = path.startsWith("http") ? path : API + path;
		const res = await fetchImpl(url, {
			headers: {
				Authorization: `Bearer ${token}`,
				Accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json",
				"User-Agent": "infiartt-bot",
				"X-GitHub-Api-Version": "2022-11-28",
			},
		});
		if (res.status === 404) return null;
		if (!res.ok) throw new Error(`GitHub GET ${path} failed: ${res.status}`);
		return raw ? res.text() : res.json();
	}

	return {
		/** Parsed JSON, or null when the resource does not exist. */
		get: (path) => request(path),
		/** File contents as text, or null when the file does not exist. */
		raw: (path) => request(path, { raw: true }),
		/** Every item of a list endpoint, following up to `maxPages` pages. */
		async all(path, maxPages = 5) {
			const items = [];
			const sep = path.includes("?") ? "&" : "?";
			for (let page = 1; page <= maxPages; page++) {
				const batch = await request(`${path}${sep}per_page=100&page=${page}`);
				if (!Array.isArray(batch) || batch.length === 0) break;
				items.push(...batch);
				if (batch.length < 100) break;
			}
			return items;
		},
	};
}
