# InfiArtt bot

A Telegram bot for the InfiArtt organization, running on Cloudflare Workers (free plan). It posts important news to the team's Telegram group and answers a few commands there. Messages are in Indonesian.

## What it reports

From GitHub, through an organization webhook (all repositories, including new ones):

- Secrets found in a repository, and pushes that bypassed push protection.
- Vulnerable dependencies of high or critical severity.
- Repositories created, deleted, made public or private, archived, renamed or transferred.
- Members joining, leaving or being invited.
- A new release of an NVDA add-on, as a reminder to submit it to the Add-on Store by hand.

CI results are deliberately not reported, so members' failed runs don't flood the group.

From the NVDA Add-on Store, checked every 30 minutes:

- A new version of one of our add-ons going live, with its VirusTotal result.
- New comments on, or the closing of, one of our submission issues.
- A new NVDA release that makes one of our add-ons incompatible.

On a schedule, within the same 30-minute cron:

- Every Monday at 08:00 WIB (01:00 UTC): a weekly digest of new issues and pull requests, merges, releases, open security alerts and add-on status.
- Every day at 09:00 WIB (02:00 UTC): a reminder when the bot's GitHub token expires in 30, 14, 7, 3, 1 or 0 days, and when the `InfiArtt/.github` workflow reports that `ORG_ADMIN_TOKEN` expires soon.

## Commands

Only in the configured group. By default every member of that group may use them, since they only read data; set `ALLOWED_USERS` to limit them to certain people. Each deploy also registers them as Telegram's "/" menu.

| Command | Shows |
| :-- | :-- |
| `/addons` | Every NVDA add-on in the organization: latest release, version in the Add-on Store, pending submissions, VirusTotal result, compatibility |
| `/status` | Counts of open secret alerts and high or critical vulnerabilities, and protected public repositories |
| `/keamanan` | Those alerts in detail, grouped by repository and package |
| `/repo` | Every repository: last push, open issues and pull requests, protection |
| `/pr` | Open pull requests across the organization, oldest first |
| `/rilis` | Each repository's latest release |
| `/nvda` | The latest stable and upcoming NVDA versions, and each add-on's compatibility (from `buildVars.py` until it is in the store) |
| `/tim` | Teams, their members and repositories (the token needs Members: Read-only) |
| `/bantuan` | Help |
| `/id` | The chat and user IDs, for setup |

## Read-only towards the Add-on Store

NV Access requires add-ons to be submitted, and submissions to be discussed, by people through the issue form, not by tools. The bot only reads public data from `nvaccess/addon-datastore`, at most every 30 minutes, and never creates issues or comments there. It doesn't even link a prefilled form.

## Setup

Secrets, in this repository's **Settings > Secrets and variables > Actions**:

| Secret | What it is |
| :-- | :-- |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token from the "Edit Cloudflare Workers" template |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID |
| `TELEGRAM_BOT_TOKEN` | From @BotFather |
| `GH_READ_TOKEN` | Fine-grained GitHub token, resource owner InfiArtt, all repositories, read-only: Contents, Administration, Dependabot alerts, Secret scanning alerts, Issues, Pull requests; organization: Members |
| `TELEGRAM_WEBHOOK_SECRET` | Random string; Telegram sends it with every update |
| `WEBHOOK_SECRET` | Random string; signs the GitHub organization webhook |
| `TELEGRAM_CHAT_ID` | The group's ID (send `/id` in the group) |
| `ALLOWED_USERS` | Optional. Who may use commands: Telegram usernames (`@name`) and/or numeric user IDs, comma-separated. Empty means everyone in the group. IDs are stricter, since a username can change hands. |

Every push to `main` runs the tests, deploys the Worker, uploads these secrets to it and points the Telegram bot at it. The GitHub organization webhook goes to `<worker URL>/github`, content type `application/json`, with the `WEBHOOK_SECRET`, for the events: Repositories, Organizations, Secret scanning alerts, Dependabot alerts and Releases.

## Development

```bash
npm ci
npm test
```

The tests replace GitHub and Telegram with fakes, so they need no network or tokens.
