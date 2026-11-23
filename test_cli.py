"""Offline tests with a real loopback listener and a simulated OpenAI provider."""

import hashlib
import http.client
import json
import os
import stat
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from threading import Thread
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import cli
import siwc
from inference import infer
from storage import StorageError, Store


class CLITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update(kid="test-key", alg="RS256", use="sig")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Store(Path(tmp.name) / "test-state")
        self.now = int(time.time())

    def client(self, handler):
        http = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(http.close)
        return http

    def id_token(self, **overrides):
        claims = {
            "iss": siwc.ISSUER, "aud": "oaiapp_test", "sub": "user",
            "iat": self.now, "exp": self.now + 600, "email": "test@example.test",
        }
        return jwt.encode(claims | overrides, self.key, algorithm="RS256", headers={"kid": "test-key"})

    def token_data(self, **overrides):
        return {
            "access_token": "access-test", "refresh_token": "refresh-test", "expires_in": 3600,
            "scope": siwc.SCOPES, "token_type": "Bearer",
        } | overrides

    def seed(self, state, **overrides):
        credentials = siwc.read_credentials(self.token_data(**overrides), self.now)
        profile = {
            "client_id": "oaiapp_test",
            "identity": {"issuer": siwc.ISSUER, "subject": "user", "email": None},
            "credentials": credentials,
        }
        state["profiles"]["default"] = profile
        state["active"] = "default"
        self.store.save(state)
        return profile

    def test_full_sign_in_and_smoke_with_loopback_callback(self):
        params, browser_checks = {}, []
        worker = None

        def simulated_browser(url):
            nonlocal worker
            auth = urlsplit(url)
            self.assertEqual(siwc.AUTHORIZE, f"{auth.scheme}://{auth.netloc}{auth.path}")
            params.update({k: v[0] for k, v in parse_qs(auth.query).items()})
            callback = urlsplit(params["redirect_uri"])
            self.assertEqual("127.0.0.1", callback.hostname)
            self.assertEqual(siwc.CALLBACK_PATH, callback.path)

            def send_callback():
                for values in (
                    [("state", "wrong"), ("code", "ignored")],
                    [("state", params["state"]), ("state", params["state"]), ("code", "ignored")],
                    [("state", params["state"]), ("code", "fixture-code"), ("client_id", "oaiapp_test")],
                ):
                    conn = http.client.HTTPConnection(callback.hostname, callback.port, timeout=2)
                    try:
                        conn.request("GET", callback.path + "?" + urlencode(values))
                        result = conn.getresponse()
                        browser_checks.append((result.status, result.read(), result.getheader("Cache-Control")))
                    finally:
                        conn.close()

            worker = Thread(target=send_callback)
            worker.start()

        def provider(request):
            if str(request.url) == siwc.TOKEN:
                form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
                self.assertEqual("authorization_code", form["grant_type"])
                self.assertEqual("oaiapp_test", form["client_id"])
                self.assertEqual("fixture-code", form["code"])
                self.assertEqual(params["redirect_uri"], form["redirect_uri"])
                self.assertEqual(siwc.RESOURCE, form["resource"])
                self.assertNotIn("client_secret", form)
                self.assertEqual("S256", params["code_challenge_method"])
                self.assertEqual(params["code_challenge"], siwc.b64url(hashlib.sha256(form["code_verifier"].encode()).digest()))
                return httpx.Response(200, json=self.token_data(id_token=self.id_token(nonce=params["nonce"])))
            if str(request.url) == siwc.JWKS:
                return httpx.Response(200, json={"keys": [self.jwk]})
            self.assertEqual("Bearer access-test", request.headers["Authorization"])
            if str(request.url) == siwc.RESOURCE + "/models":
                return httpx.Response(200, json={"models": [
                    {"slug": "hidden", "visibility": "hidden"},
                    {"slug": "visible", "visibility": "list"},
                ]})
            self.assertEqual(siwc.RESOURCE + "/responses", str(request.url))
            self.assertEqual("POST", request.method)
            body = json.loads(request.content)
            self.assertEqual({"model", "input", "store", "stream"}, set(body))
            self.assertEqual("visible", body["model"])
            self.assertIs(body["store"], False)
            self.assertIs(body["stream"], True)
            return httpx.Response(
                200, headers={"Content-Type": "text/event-stream"},
                text='data: {"type":"response.output_text.delta","delta":"Hello, world!"}\n\n'
                     'data: {"type":"response.completed"}\n\n',
            )

        client = self.client(provider)
        await_result = siwc.CallbackServer.await_result
        with (
            self.store.locked() as state,
            patch.object(siwc, "open_browser", simulated_browser),
            patch.object(siwc.CallbackServer, "await_result", lambda server: await_result(server, 6)),
        ):
            with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()):
                cli.run(cli.parse_args(["login"]), client, self.store, state)
                cli.run(cli.parse_args(["smoke"]), client, self.store, state)
            self.assertIn("Hello, world!", output.getvalue())
            self.assertEqual("default", state["active"])
            self.assertEqual(state["host_id"], params["ext_agent_host_id"])
            self.assertEqual(siwc.DYNAMIC_CLIENT, params["client_id"])
            self.assertEqual(siwc.APP_NAME, params["agent_name_hint"])
        worker.join(timeout=2)
        self.assertEqual([400, 400, 200], [status for status, _, _ in browser_checks])
        self.assertNotIn(b"fixture-code", browser_checks[-1][1])
        self.assertEqual("no-store", browser_checks[-1][2])

    def test_returning_callback_requires_the_saved_client(self):
        self.assertEqual(("code", "oaiapp_test"), siwc.callback_result({"code": ["code"]}, "oaiapp_test"))
        with self.assertRaisesRegex(siwc.AppError, "unexpected registration"):
            siwc.callback_result({"code": ["code"], "client_id": ["oaiapp_other"]}, "oaiapp_test")
        with self.assertRaisesRegex(siwc.AppError, "declined"):
            siwc.callback_result({"code": ["code"], "error": ["access_denied"]}, "oaiapp_test")
        with self.assertRaisesRegex(siwc.AppError, "issued client ID"):
            siwc.callback_result({"code": ["code"], "client_id": [siwc.DYNAMIC_CLIENT]}, None)

    def test_token_rejects_wrong_identity_claims_or_signature(self):
        http = self.client(lambda _: httpx.Response(200, json={"keys": [self.jwk]}))
        for claim in (
            {"iss": "https://invalid.test"},
            {"aud": "oaiapp_other"},
            {"exp": self.now - 60, "iat": self.now - 120},
            {"nonce": "wrong"},
            {"at_hash": "wrong"},
            {"azp": "oaiapp_other"},
        ):
            with self.subTest(claim=claim), self.assertRaises(siwc.InvalidCredentials):
                data = self.token_data(id_token=self.id_token(**({"nonce": "expected"} | claim)))
                siwc.verify_identity(http, siwc.read_credentials(data, self.now), "oaiapp_test", "expected")
        parts = self.id_token(nonce="expected").split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        with self.assertRaises(siwc.InvalidCredentials):
            data = self.token_data(id_token=".".join(parts))
            siwc.verify_identity(http, siwc.read_credentials(data, self.now), "oaiapp_test", "expected")

    def test_identity_only_cannot_reach_a_plan_endpoint(self):
        http = self.client(lambda _: self.fail("An outbound request was made"))
        with self.store.locked() as state:
            profile = self.seed(state, scope="openid profile email", refresh_token=None)
            with self.assertRaisesRegex(siwc.AppError, "plan usage is disabled"):
                cli.plan_token(http, self.store, state, profile, "default")

    def test_refresh_recovers_after_signing_key_outage_without_replaying_grant(self):
        counters = {"refresh": 0, "keys": 0}

        def provider(request):
            if str(request.url) == siwc.TOKEN:
                counters["refresh"] += 1
                form = parse_qs(request.content.decode())
                self.assertEqual(["refresh_token"], form["grant_type"])
                self.assertEqual(["refresh-test"], form["refresh_token"])
                self.assertEqual(["oaiapp_test"], form["client_id"])
                self.assertEqual([siwc.RESOURCE], form["resource"])
                self.assertNotIn("scope", form)
                data = self.token_data(
                    access_token="new-access", refresh_token="new-refresh", id_token=self.id_token(),
                )
                del data["scope"]
                return httpx.Response(200, json=data)
            self.assertEqual(siwc.JWKS, str(request.url))
            counters["keys"] += 1
            if counters["keys"] == 1:
                return httpx.Response(503, json={"detail": "temporary"})
            return httpx.Response(200, json={"keys": [self.jwk]})

        http = self.client(provider)
        with self.store.locked() as state:
            profile = self.seed(state)
            with self.assertRaises(siwc.RemoteError):
                cli.refresh(http, self.store, state, profile)
        with self.store.locked() as state:
            profile = state["profiles"]["default"]
            self.assertEqual("new-access", cli.plan_token(http, self.store, state, profile, "default"))
            self.assertEqual("new-refresh", profile["credentials"]["refresh_token"])
            self.assertNotIn("pending_refresh", profile)
        self.assertEqual({"refresh": 1, "keys": 2}, counters)

    def test_refresh_respects_earliest_and_retires_terminal_tokens(self):
        http = self.client(lambda _: httpx.Response(400, json={"error": "invalid_grant"}))
        with self.store.locked() as state:
            profile = self.seed(state, earliest_refresh_at=self.now + 600)
            with self.assertRaisesRegex(siwc.AppError, "refresh window"):
                cli.refresh(http, self.store, state, profile)
            self.assertIn("credentials", profile)
            profile["credentials"]["earliest_refresh_at"] = 0
            with self.assertRaisesRegex(siwc.AppError, "invalid_grant"):
                cli.refresh(http, self.store, state, profile)
            self.assertEqual("oaiapp_test", profile["client_id"])
            self.assertNotIn("credentials", profile)

    def test_requests_renew_near_expiry_without_a_new_id_token(self):
        def provider(request):
            self.assertEqual(siwc.TOKEN, str(request.url))
            return httpx.Response(200, json=self.token_data(
                access_token="new-access", refresh_token="new-refresh",
            ))

        http = self.client(provider)
        with self.store.locked() as state:
            old_id_token = self.id_token()
            profile = self.seed(state, expires_in=15, id_token=old_id_token)
            self.assertEqual("new-access", cli.plan_token(http, self.store, state, profile, "default"))
            self.assertEqual(old_id_token, profile["credentials"]["id_token"])

    def test_refresh_rejects_a_different_subject(self):
        def provider(request):
            if str(request.url) == siwc.JWKS:
                return httpx.Response(200, json={"keys": [self.jwk]})
            return httpx.Response(200, json=self.token_data(
                refresh_token="new-refresh", id_token=self.id_token(sub="another-user"),
            ))

        http = self.client(provider)
        with self.store.locked() as state:
            profile = self.seed(state)
            with self.assertRaisesRegex(siwc.AppError, "different account"):
                cli.refresh(http, self.store, state, profile)
            self.assertEqual("user", profile["identity"]["subject"])
            self.assertNotIn("credentials", profile)
            self.assertNotIn("pending_refresh", profile)

    def test_storage_permissions_and_exclusive_lock(self):
        with self.store.locked() as state:
            self.seed(state)
            with self.assertRaisesRegex(StorageError, "Another CLI command"):
                with self.store.locked():
                    self.fail("The lock was acquired twice")
        self.assertEqual(0o700, stat.S_IMODE(self.store.directory.stat().st_mode))
        self.assertEqual(0o600, stat.S_IMODE(self.store.path.stat().st_mode))
        os.chmod(self.store.path, 0o644)
        with self.assertRaises(StorageError):
            with self.store.locked():
                self.fail("An insecure session file was opened")

    def test_inference_requires_completion_and_surfaces_usage_errors(self):
        for events, expected in (
            ('data: {"type":"response.output_text.delta","delta":"partial"}\n\n', "before the completion event"),
            ('data: {"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}}\n\n',
             "subscription_sharing_usage_limit_exceeded"),
            ('data: {"type":"response.incomplete","response":{"incomplete_details":{"reason":"content_filter"}}}\n\n',
             "content_filter"),
        ):
            with self.subTest(expected=expected):
                http = self.client(lambda _: httpx.Response(
                    200, text=events,
                    headers={"Content-Type": "text/event-stream", "x-request-id": "req_fixture"},
                ))
                with self.assertRaisesRegex(siwc.AppError, expected + ".*req_fixture"):
                    infer(http, "access-test", "visible", "Test")

    def test_logout_revokes_with_discovered_endpoint_and_keeps_registration(self):
        endpoint = siwc.ISSUER + "/api/accounts/oauth/revoke"

        def provider(request):
            if str(request.url) == siwc.DISCOVERY:
                return httpx.Response(200, json={"issuer": siwc.ISSUER, "revocation_endpoint": endpoint})
            self.assertEqual(endpoint, str(request.url))
            self.assertEqual({
                "token": ["refresh-test"], "token_type_hint": ["refresh_token"], "client_id": ["oaiapp_test"],
            }, parse_qs(request.content.decode()))
            return httpx.Response(200)

        with self.store.locked() as state, redirect_stdout(StringIO()):
            profile = self.seed(state)
            cli.logout(self.client(provider), self.store, state, profile)
            self.assertNotIn("credentials", profile)
            self.assertEqual("oaiapp_test", profile["client_id"])


if __name__ == "__main__":
    unittest.main()
