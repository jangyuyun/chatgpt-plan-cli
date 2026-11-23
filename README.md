# ChatGPT Plan CLI

A Python CLI for signing in with ChatGPT and making eligible text inference requests using the selected ChatGPT account’s plan. It runs locally on macOS or desktop Linux. It uses OpenAI’s documented public-client flow and requires neither an API key nor a client secret.

## Eligibility and registration

- **Open-source local apps.** OpenAI’s open-source developer guide documents dynamic registration during browser sign-in. OpenAI binds the issued client ID to the user and selected workspace. Sign-in and consent to use the plan are separate. OpenAI’s developer quickstart identifies eligible Plus and Pro accounts for this flow. Its Help Center also documents Go, Plus, Pro, and Business for participating commercial apps and says supported open-source tools are available to all ChatGPT users. Actual inference eligibility depends on the account, workspace, rollout, and policy at request time. [Developer quickstart](https://developers.openai.com/siwc/quickstart) · [Open-source guide](https://developers.openai.com/siwc/token-sharing-open-source) · [Help Center eligibility](https://help.openai.com/en/articles/20001542-using-your-chatgpt-plan-in-other-apps-and-sites)
- **Paid or remotely hosted products.** OpenAI directs commercial developers to its interest form. Selected partners receive their own registration and any approval needed for plan usage. Website identity-only sign-in uses a separate client and callback configuration. This CLI implements the public local flow and its browser callback requires the same machine as the browser. [Partner interest form](https://openai.com/form/sign-in-with-chatgpt-interest/) · [Website OAuth guide](https://developers.openai.com/siwc/website)
- **Billing and API coverage.** This app uses the account’s authorized ChatGPT allowance or eligible ChatGPT credits, subject to the user’s and workspace’s settings. The integration supports an account-specific model catalog and eligible Responses calls. Ordinary API-key usage has separate billing. Eligible Pro and Business customers may have a separate API credit benefit. Chat Completions, Files uploads, hosted image generation, and other routes or capabilities outside the documented preview are unsupported here. [Models and inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference) · [Preview limits](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations) · [API billing](https://help.openai.com/en/articles/9039756-managing-billing-for-chatgpt-and-the-api-platform) · [API credit benefit](https://help.openai.com/en/articles/20001626-api-credits-benefit-for-eligible-chatgpt-subscriptions)

## Install and run

Use uv with Python 3.12 or newer on macOS or desktop Linux. On Linux the session needs `xdg-open` and a default graphical browser. Extract the archive, open a terminal in the `chatgpt-plan-cli` directory, and run these commands.

```sh
uv sync --locked

uv run cli.py login
uv run cli.py status
uv run cli.py models
uv run cli.py smoke
```

In the browser, select the intended account and workspace. Review and approve the optional permission to use your ChatGPT plan. If you decline that permission and OpenAI returns a valid identity token, `status` will show plan usage as disabled.

`smoke` sends one live text request, using the first visible model returned for the account by default. Expect `Hello, world!` and exit status `0` only after a completed Responses stream. This request uses your ChatGPT plan and can consume allowance or available ChatGPT credits according to your settings. [ChatGPT usage settings](https://chatgpt.com/settings/usage)

```sh
# Replace MODEL_SLUG with a slug from the models command.
uv run cli.py smoke --model MODEL_SLUG
uv run cli.py ask --model MODEL_SLUG 'Summarize how PKCE works in two sentences.'
uv run cli.py ask --model MODEL_SLUG --stdin < prompt.txt

# Reopen consent for a profile, or save a second account or workspace.
uv run cli.py login --enable-plan
uv run cli.py login work
uv run cli.py use default

uv run cli.py refresh  # Optional, only once OpenAI permits renewal
uv run cli.py logout
uv run python -m unittest -v
```

`login` without a label reuses the active registration or creates the `default` profile on first run. A new label starts a separate registration. `status` displays the active profile and locally granted permission. The model request can still return an eligibility or usage-limit error. `logout` ends the active renewable session when the provider confirms revocation and clears its local tokens. If revocation fails, use ChatGPT Settings → Security and login → Login connections to disconnect the app.

## How the CLI handles credentials

- **Browser authorization.** The CLI saves a random UUID host identifier and binds a one-time callback to `http://127.0.0.1:<port>/auth/callback` before launching the browser. It generates fresh state, a nonce, and an S256 PKCE challenge for each attempt. It accepts a callback only on the expected path and host, checks state before handling the result, and binds the code exchange to the same redirect URI and the OpenAI-issued client ID. Returning sign-ins reuse the registration and validate the same subject. The CLI keeps the optional ID-token hint out of browser URLs. [Registration and sign-in](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
- **Validation and inference.** The CLI verifies the RS256 ID-token signature using OpenAI’s JWKS and checks issuer, audience, timestamps, nonce, and subject. It checks `azp` and `at_hash` when present. It uses only the access token as a bearer credential for the fixed OpenAI resource. Both `resource.invoke` and `chatgpt.tokens.use.direct` must be granted. Requests use `store: false` and `stream: true`, and partial streams exit with an error. API-key billing fallback is disabled. [OpenID discovery](https://auth.openai.com/.well-known/openid-configuration) · [Token reference](https://developers.openai.com/siwc/token-sharing-open-source/token-reference) · [Inference contract](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
- **Storage and rotation.** Session records live in `~/.config/chatgpt-plan-cli/sessions.json`, in an owner-only `0700` directory with `0600` files. This uses OS file permissions for protection. Use a trusted local user account and keep the directory out of backups or shared folders that expose its contents. The file is replaced atomically under a lock. Requests renew near expiry if OpenAI’s refresh window is open. The CLI checkpoints a replacement token before looking up signing keys and verifies any refreshed identity before enabling the new credentials. Terminal refresh errors clear the tokens and preserve the client registration. A process or network failure immediately after server-side rotation can still require signing in again. [Accounts and sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions) · [Errors and recovery](https://developers.openai.com/siwc/token-sharing-open-source/errors-and-recovery)

## Troubleshooting

| What you see | What to do |
| --- | --- |
| Browser failed to open or timed out | Check the default desktop browser and run `login` again on the same machine. |
| ChatGPT plan usage is disabled | Run `login --enable-plan` and review the consent options for the intended account. |
| HTTP 401 or an unusable refresh token | Check `status`. If the session was cleared or the app was disconnected in ChatGPT, run `login` again. |
| HTTP 403 or account ineligible | Check the account, workspace administrator permissions, app access, and serving-region policy. |
| Usage limit or temporary usage-service error | Review ChatGPT usage settings for a limit, or try later if the service is temporarily unavailable. |
| Callback works but the code exchange fails | Run `login` again with the same label to obtain a fresh code for the saved registration. |

The automated tests use a real loopback callback and simulated OpenAI endpoints. They cover registration, PKCE, account claims, plan consent, token rotation, file permissions, revocation, and completed inference. `smoke` is the separate live test and requires your own sign-in and consent.

Official documentation checked November 23, 2026.
