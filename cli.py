#!/usr/bin/env python3
"""Local CLI for subscription-backed Sign in with ChatGPT."""

import argparse
import re
import sys
import time

import httpx

from inference import infer, list_models
from siwc import (
    AppError, InvalidCredentials, PLAN_SCOPES, RemoteError, TERMINAL_REFRESH_ERRORS, USAGE_URL,
    authorize, read_credentials, revoke, token_request, verify_identity,
)
from storage import StorageError, Store

PLAN_HELP = {
    "subscription_sharing_user_not_eligible": "The selected account or workspace is ineligible for plan usage.",
    "subscription_sharing_usage_limit_exceeded": f"Review your app and plan limits at {USAGE_URL}.",
    "subscription_sharing_usage_unavailable": "Usage verification is unavailable. Try again later.",
    "subscription_sharing_user_unavailable": "Workspace information is unavailable. Try again later.",
    "subscription_sharing_invalid_user": "Check the selected profile and its ChatGPT connection.",
    "chatpass_v2_scope_not_authorized": "Check the permissions granted to this connection.",
    "chatpass_v2_invalid_authorization_context": "Check the permissions granted to this connection.",
    "invalid_client": "Check this registration in ChatGPT Settings. A different workspace needs a separate profile.",
}


def safe_text(text):
    # Keep terminal escapes and other control characters inert, while retaining newlines.
    return "".join(char if char in "\n\t" or char.isprintable() else "\N{REPLACEMENT CHARACTER}" for char in text)


def sharing(credentials):
    return bool(credentials and PLAN_SCOPES.issubset(credentials["scopes"]))


def identity_for(http, profile, credentials, nonce=None):
    identity = verify_identity(http, credentials, profile["client_id"], nonce)
    previous = profile.get("identity")
    if previous and (previous["issuer"], previous["subject"]) != (identity["issuer"], identity["subject"]):
        raise InvalidCredentials("OpenAI returned a different account. Select the original account or use a different profile label.")
    return identity


def login(http, store, state, label, enable_plan):
    profiles = state["profiles"]
    profile = profiles.get(label)
    client_id, nonce, exchange = authorize(state["host_id"], profile["client_id"] if profile else None, enable_plan)
    if profile is None:
        if any(other["client_id"] == client_id for other in profiles.values()):
            raise AppError("That registration already has a local profile. Use its label to sign in again.")
        profile = {"client_id": client_id}
        profiles[label] = profile
        # Retain the registration if the one-time code expires or verification fails.
        store.save(state)

    try:
        data, received_at = token_request(http, grant_type="authorization_code", client_id=client_id, **exchange)
    except RemoteError as error:
        if error.code == "invalid_grant":
            raise AppError(f"{error}. Run login {label} again to get a fresh authorization code.") from None
        raise
    credentials = read_credentials(data, received_at)
    profile["identity"] = identity_for(http, profile, credentials, nonce)
    profile["credentials"] = credentials
    profile.pop("pending_refresh", None)
    state["active"] = label
    store.save(state)


def refresh(http, store, state, profile):
    current = profile.get("credentials")
    pending = profile.get("pending_refresh")
    try:
        if pending is None:
            if not current or not current["refresh_token"]:
                raise AppError("No renewable session. Run login again.")
            if time.time() < current["earliest_refresh_at"]:
                raise AppError("OpenAI's refresh window has not opened. Try again when the token is closer to expiry.")
            data, received_at = token_request(
                http, grant_type="refresh_token", client_id=profile["client_id"],
                refresh_token=current["refresh_token"],
            )
            pending = read_credentials(data, received_at, current)
            if pending["id_token"]:
                # Persist rotation before any network-dependent check. Pending credentials
                # cannot authorize inference until their identity has been validated.
                profile["pending_refresh"] = pending
                store.save(state)
        if pending["id_token"]:
            profile["identity"] = identity_for(http, profile, pending)
        else:
            pending["id_token"] = current["id_token"]
        profile["credentials"] = pending
        profile.pop("pending_refresh", None)
        store.save(state)
    except (RemoteError, InvalidCredentials) as error:
        if isinstance(error, InvalidCredentials) or error.code in TERMINAL_REFRESH_ERRORS:
            profile.pop("credentials", None)
            profile.pop("pending_refresh", None)
            store.save(state)
            raise AppError(f"{error} Run login again to reuse this registration.") from None
        raise
    return profile["credentials"]


def plan_token(http, store, state, profile, label):
    current = profile.get("credentials")
    if profile.get("pending_refresh"):
        current = refresh(http, store, state, profile)
    if not current:
        raise AppError(f"Run login {label} to connect this profile.")
    if not sharing(current):
        raise AppError(f"ChatGPT plan usage is disabled. To review consent, run login {label} --enable-plan.")
    now = time.time()
    if now + 60 >= current["expires_at"] and now >= current["earliest_refresh_at"]:
        current = refresh(http, store, state, profile)
    if not sharing(current):
        raise AppError(f"ChatGPT plan usage is disabled. To review consent, run login {label} --enable-plan.")
    if current["expires_at"] <= time.time():
        raise AppError("The access token expired before it could be refreshed. Try again when renewal is available.")
    return current["access_token"]


def logout(http, store, state, profile):
    credentials = profile.get("pending_refresh") or profile.get("credentials")
    if not credentials:
        print("This profile is already signed out.")
        return
    try:
        if not credentials["refresh_token"]:
            raise AppError("This session has no refresh token to revoke.")
        revoke(http, profile["client_id"], credentials["refresh_token"])
    except (AppError, httpx.RequestError, KeyboardInterrupt):
        raise AppError(
            "Signed out locally. Remote revocation could not be confirmed. "
            "Disconnect the app in ChatGPT Settings → Security and login."
        ) from None
    finally:
        profile.pop("credentials", None)
        profile.pop("pending_refresh", None)
        store.save(state)
    print("Signed out and revoked the renewable session.")


def show_status(state):
    if not state["profiles"]:
        print("No profiles. Run login to continue with ChatGPT.")
        return
    for label, profile in sorted(state["profiles"].items()):
        active = " (active)" if state["active"] == label else ""
        identity = profile.get("identity")
        email = safe_text(identity["email"]).replace("\n", " ").replace("\t", " ") if identity and identity["email"] else ""
        credentials = profile.get("credentials")
        if profile.get("pending_refresh"):
            status = "refresh verification pending"
        elif credentials:
            plan = "enabled" if sharing(credentials) else "disabled"
            status = f"signed in · ChatGPT plan usage {plan}"
            if credentials["expires_at"] <= time.time():
                status += " · access token expired"
        else:
            status = "signed out" if identity else "registration awaiting sign-in"
        print("  ".join(part for part in (label + active, email, status) if part))
    print(f"Manage plan usage at {USAGE_URL}")


def profile_label(value):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}", value):
        raise argparse.ArgumentTypeError("Use 1–32 letters, digits, underscores or hyphens, starting with a letter or digit.")
    return value


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sign_in = commands.add_parser("login", help="continue with ChatGPT in your browser")
    sign_in.add_argument("label", type=profile_label, nargs="?")
    sign_in.add_argument("--enable-plan", action="store_true", help="explicitly request plan consent again")
    commands.add_parser("status", help="show profiles, active account, and plan permission")
    commands.add_parser("use", help="select a saved profile").add_argument("label", type=profile_label)
    commands.add_parser("logout", help="revoke and clear the active profile's session")
    commands.add_parser("refresh", help="renew the active profile once renewal is available")
    commands.add_parser("models", help="list models available with the selected ChatGPT connection")
    ask = commands.add_parser("ask", help="send a text prompt using your ChatGPT plan")
    ask.add_argument("--model", required=True, help="a slug from the models command")
    ask.add_argument("--stdin", action="store_true", help="read the prompt from standard input")
    ask.add_argument("prompt", nargs="?")
    smoke = commands.add_parser("smoke", help="run a live Hello, world! request using your ChatGPT plan")
    smoke.add_argument("--model", help="a slug from models; defaults to the first visible model")
    args = parser.parse_args(argv)
    if args.command == "ask" and args.stdin == (args.prompt is not None):
        ask.error("provide a prompt or use --stdin")
    return args


def run(args, http, store, state):
    command = args.command
    label = getattr(args, "label", None) or state["active"] or "default"
    profile = state["profiles"].get(label)
    if command == "status":
        show_status(state)
        return
    if command == "login":
        store.save(state)  # Persist the host ID before its first authorization.
        login(http, store, state, label, args.enable_plan)
        show_status(state)
        return
    if not profile:
        raise AppError(f"Profile {label} is missing. Run login {label}.")
    if command == "use":
        if not profile.get("identity"):
            raise AppError(f"Run login {label} to verify this profile's account.")
        state["active"] = label
        store.save(state)
        print(f"Active profile is {label}.")
        return
    if command == "logout":
        logout(http, store, state, profile)
        return
    if command == "refresh":
        refresh(http, store, state, profile)
        show_status(state)
        return

    prompt = ""
    if command == "ask":
        prompt = sys.stdin.read() if args.stdin else args.prompt
        if not prompt.strip():
            raise AppError("The prompt is empty.")

    token = plan_token(http, store, state, profile, label)
    print(f"Using your ChatGPT plan for {label}. Manage usage at {USAGE_URL}", file=sys.stderr)
    if command == "models":
        for slug, name in list_models(http, token):
            print(f"{safe_text(slug)}\t{safe_text(str(name))}")
        return

    model = args.model
    if command == "smoke":
        prompt = "Reply with exactly these characters: Hello, world!"
        if not model:
            models = list_models(http, token)
            if not models:
                raise AppError("No visible models are available for this connection.")
            model = models[0][0]
        print(f"Testing {safe_text(model)}…", file=sys.stderr)
    output = infer(http, token, model, prompt)
    if not output:
        raise AppError("The request completed without a text response.")
    print(safe_text(output))
    if command == "smoke" and output.strip() != "Hello, world!":
        raise AppError("Inference completed, but the smoke test received unexpected text.")


def main(argv=None):
    args = parse_args(argv)
    store = Store()
    try:
        # Hold the lock across commands, including refresh and inference, so a second
        # process cannot rotate or use the current session while it is being revoked.
        with store.locked() as state, httpx.Client(
            timeout=httpx.Timeout(90.0, connect=10.0), follow_redirects=False, trust_env=False,
        ) as http:
            run(args, http, store, state)
    except RemoteError as error:
        help_text = PLAN_HELP.get(error.code)
        print(error, file=sys.stderr)
        if help_text:
            print(help_text, file=sys.stderr)
        return 1
    except (AppError, StorageError) as error:
        print(error, file=sys.stderr)
        return 1
    except httpx.RequestError:
        print("OpenAI could not be reached over HTTPS. Check your network and try again.", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Local operation failed ({error.strerror or 'I/O error'}). Check file permissions and local networking.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
