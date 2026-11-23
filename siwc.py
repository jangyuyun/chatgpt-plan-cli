"""OpenAI Sign in with ChatGPT for a public loopback OAuth client."""

import base64
import hashlib
import hmac
import math
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue
from socketserver import TCPServer
from threading import Lock
from urllib.parse import parse_qs, urlencode

import httpx
import jwt

APP_NAME = "ChatGPT Plan CLI"
ISSUER = "https://auth.openai.com"
AUTHORIZE = ISSUER + "/api/accounts/authorize"
TOKEN = ISSUER + "/api/accounts/oauth/token"
DISCOVERY = ISSUER + "/.well-known/openid-configuration"
JWKS = ISSUER + "/.well-known/jwks.json"
RESOURCE = "https://api.openai.com/v1"
DYNAMIC_CLIENT = "dynamic_agent_client"
CALLBACK_PATH = "/auth/callback"
PLAN_SCOPES = {"resource.invoke", "chatgpt.tokens.use.direct"}
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
TERMINAL_REFRESH_ERRORS = {
    "invalid_grant", "invalid_refresh_token", "token_expired",
    "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused",
}
USAGE_URL = "https://chatgpt.com/settings/usage"
BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*")
CLIENT_ID = re.compile(r"[A-Za-z0-9_-]{1,200}")


class AppError(Exception):
    pass


class InvalidCredentials(AppError):
    pass


class RemoteError(AppError):
    def __init__(self, action, status, code, request_id, *, shape=None, param=None):
        self.code = diagnostic(code)
        parts = [action, f"HTTP {status}"]
        parts.extend(part for part in (shape, self.code) if part)
        if diagnostic(param):
            parts.append(f"parameter {param}")
        if diagnostic(request_id):
            parts.append(f"request ID {request_id}")
        super().__init__(", ".join(parts))


def diagnostic(value):
    # Free-form provider messages and response bodies may echo sensitive inputs.
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.\[\]-]{1,160}", value) else None


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def same(left, right):
    return isinstance(left, str) and hmac.compare_digest(left.encode("utf-8", "surrogatepass"), right.encode())


def auth_url(redirect_uri, host_id, client_id, state, nonce, verifier, enable_plan):
    params = {
        "client_id": client_id or DYNAMIC_CLIENT,
        "ext_agent_host_id": host_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "resource": RESOURCE,
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
    }
    if not client_id:
        params["agent_name_hint"] = APP_NAME
    if client_id and enable_plan:
        params["prompt"] = "consent"
    return AUTHORIZE + "?" + urlencode(params)


def callback_result(query, client_id):
    if "iss" in query and query["iss"] != [ISSUER]:
        raise AppError("The callback returned an unexpected issuer.")
    if "error" in query:
        if query["error"] == ["access_denied"]:
            raise AppError("ChatGPT authorization was declined. Try login again when ready.")
        code = diagnostic(query["error"][0])
        raise AppError(f"ChatGPT authorization failed ({code or 'unknown error'}).")
    code = query.get("code")
    returned = query.get("client_id", [])
    if len(returned) > 1 or (returned and client_id and returned[0] != client_id):
        raise AppError("The callback returned an unexpected registration.")
    issued = returned[0] if returned else client_id
    if not issued or not CLIENT_ID.fullmatch(issued) or issued == DYNAMIC_CLIENT:
        raise AppError("OpenAI did not return an issued client ID. Try login again.")
    if not code or len(code) != 1 or not code[0] or len(code[0]) > 8192:
        raise AppError("The callback did not contain one valid authorization code.")
    return code[0], issued


# The page contains no callback data, and removes the code from the address bar.
CALLBACK_SCRIPT = b'history.replaceState(null, "", "/auth/complete");'
SCRIPT_HASH = base64.b64encode(hashlib.sha256(CALLBACK_SCRIPT).digest()).decode("ascii")
CALLBACK_PAGE = (
    b'<!doctype html><html lang="en"><meta charset="utf-8">'
    b"<title>Return to the CLI</title><h1>Return to the CLI</h1>"
    b"<p>Check the terminal for your sign-in result. You can close this tab.</p>"
    b"<script>" + CALLBACK_SCRIPT + b"</script></html>"
)


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def reply(self, status, body, *, callback_page=False):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8" if callback_page else "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        policy = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        if callback_page:
            policy += f"; script-src 'sha256-{SCRIPT_HASH}'"
        self.send_header("Content-Security-Policy", policy)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        server = self.server
        target, _, raw_query = self.path.partition("?")
        if target != CALLBACK_PATH or self.headers.get_all("Host") != [server.host_header]:
            self.reply(404, b"Not found.")
            return
        try:
            query = parse_qs(raw_query, keep_blank_values=True, max_num_fields=32, errors="strict")
        except ValueError:
            self.reply(400, b"Invalid callback.")
            return
        state = query.get("state", [])
        if len(state) != 1 or not same(state[0], server.state):
            self.reply(400, b"Sign-in state did not match. Return to the tab that started sign-in.")
            return

        with server.claim:
            if server.used:
                self.reply(410, b"This sign-in attempt has ended.")
                return
            server.used = True

        try:
            result = callback_result(query, server.client_id)
        except AppError as error:
            result = error
        try:
            self.reply(200, CALLBACK_PAGE, callback_page=True)
        finally:
            server.results.put_nowait(result)


class CallbackServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def server_bind(self):
        # HTTPServer normally attempts reverse DNS even for numeric loopback.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address

    def __init__(self, state, client_id):
        super().__init__(("127.0.0.1", 0), CallbackHandler)
        self.host_header = f"127.0.0.1:{self.server_port}"
        self.redirect_uri = f"http://{self.host_header}{CALLBACK_PATH}"
        self.state = state
        self.client_id = client_id
        self.results = Queue(maxsize=1)
        self.claim = Lock()
        self.used = False
        self.timeout = 0.25

    def handle_error(self, *_):
        # BaseServer would print request context and tracebacks.
        pass

    def await_result(self, seconds=300):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.handle_request()
            try:
                result = self.results.get_nowait()
            except Empty:
                continue
            if isinstance(result, AppError):
                raise result
            return result
        raise AppError("Browser sign-in timed out. Run login again.")


def open_browser(url):
    command = ["/usr/bin/open"] if sys.platform == "darwin" else ["xdg-open"]
    try:
        subprocess.run(
            command + [url], check=True, timeout=15,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        raise AppError("Could not open the desktop browser. Check your default browser and run login again.") from None


def authorize(host_id, client_id, enable_plan):
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    with CallbackServer(state, client_id) as listener:
        redirect = listener.redirect_uri
        url = auth_url(redirect, host_id, client_id, state, nonce, verifier, enable_plan)
        print("Continue with ChatGPT in your browser…", file=sys.stderr)
        open_browser(url)
        code, issued = listener.await_result()
    return issued, nonce, {"code": code, "code_verifier": verifier, "redirect_uri": redirect}


def object_body(response):
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def check_http(response, action):
    if response.is_success:
        return
    response.read()
    body = object_body(response)
    error = body.get("error")
    if isinstance(error, dict):
        code, param, shape = error.get("code"), error.get("param"), "structured error"
    elif isinstance(error, str):
        code, param, shape = error, None, "OAuth error"
    else:
        code, param = body.get("code"), body.get("param")
        shape = "admission detail" if "detail" in body else "unrecognized error"
    raise RemoteError(action, response.status_code, code, response.headers.get("x-request-id"), shape=shape, param=param)


def token_request(http, **fields):
    response = http.post(TOKEN, data={**fields, "resource": RESOURCE})
    received_at = time.time()
    check_http(response, "Token exchange")
    return object_body(response), received_at


def read_earliest(value):
    if type(value) is int or (type(value) is float and math.isfinite(value)):
        return value
    if isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if timestamp.tzinfo is not None:
                return timestamp.timestamp()
        except (ValueError, OverflowError, OSError):
            pass
    raise InvalidCredentials("OpenAI returned an invalid earliest_refresh_at value.")


def read_credentials(data, received_at, previous=None):
    scope = data.get("scope", " ".join(previous["scopes"]) if previous else "")
    if not isinstance(scope, str):
        raise InvalidCredentials("OpenAI returned an invalid OAuth scope list.")
    scopes = sorted(set(scope.split()))
    access = data.get("access_token")
    refresh = data.get("refresh_token")
    id_token = data.get("id_token")
    expiry = data.get("expires_in")
    if (
        not isinstance(access, str) or not BEARER.fullmatch(access)
        or not isinstance(data.get("token_type"), str) or data["token_type"].lower() != "bearer"
        or type(expiry) is not int or not 0 < expiry <= 86400
        or (refresh is not None and (not isinstance(refresh, str) or not BEARER.fullmatch(refresh)))
        or ((previous is not None or "offline_access" in scopes) and not refresh)
        or (previous is not None and refresh == previous["refresh_token"])
        or ("id_token" in data and (not isinstance(id_token, str) or not id_token))
    ):
        raise InvalidCredentials("OpenAI returned an invalid token response. Sign in again.")
    earliest = data.get("earliest_refresh_at")
    return {
        "access_token": access,
        "refresh_token": refresh,
        "id_token": id_token,
        "received_at": received_at,
        "expires_at": received_at + expiry,
        "earliest_refresh_at": read_earliest(earliest) if earliest is not None else 0,
        "scopes": scopes,
    }


def verify_identity(http, credentials, client_id, nonce=None):
    token = credentials.get("id_token")
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError
    except (jwt.PyJWTError, ValueError, TypeError):
        raise InvalidCredentials("OpenAI did not return a supported signed ID token.") from None

    response = http.get(JWKS)
    check_http(response, "Signing key retrieval")
    keys = object_body(response).get("keys")
    if not isinstance(keys, list):
        raise AppError("OpenAI's signing keys are temporarily unavailable.")
    candidates = [
        key for key in keys
        if isinstance(key, dict) and key.get("kid") == header["kid"] and key.get("kty") == "RSA"
        and key.get("alg", "RS256") == "RS256" and key.get("use", "sig") == "sig"
    ]
    if len(candidates) != 1:
        raise AppError("OpenAI's matching signing key is unavailable. Try again shortly.")
    try:
        key = jwt.PyJWK.from_dict(candidates[0], algorithm="RS256").key
        if key.key_size < 2048:
            raise ValueError
        # Check dates at receipt so a saved refresh can resume after a JWKS outage.
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=ISSUER, audience=client_id,
            options={
                "require": ["iss", "aud", "exp", "iat", "sub"],
                "verify_exp": False, "verify_iat": False, "verify_nbf": False,
            },
        )
        now = credentials["received_at"]
        issued, expires, not_before = claims["iat"], claims["exp"], claims.get("nbf", claims["iat"])
        if any(type(value) is not int for value in (issued, expires, not_before)):
            raise ValueError
        if issued > now + 30 or not_before > now + 30 or expires <= now - 30 or expires <= issued:
            raise ValueError
        audience = claims["aud"]
        if (isinstance(audience, list) and len(audience) > 1) or "azp" in claims:
            if claims.get("azp") != client_id:
                raise ValueError
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise ValueError
        if nonce is not None and not same(claims.get("nonce"), nonce):
            raise ValueError
        if "at_hash" in claims:
            digest = hashlib.sha256(credentials["access_token"].encode("ascii")).digest()
            if not same(claims["at_hash"], b64url(digest[:16])):
                raise ValueError
    except (jwt.PyJWTError, ValueError, TypeError, OverflowError):
        raise InvalidCredentials("OpenAI ID-token validation failed. Sign in again.") from None

    email = claims.get("email")
    return {"issuer": ISSUER, "subject": claims["sub"], "email": email if isinstance(email, str) else None}


def revoke(http, client_id, refresh_token):
    response = http.get(DISCOVERY)
    check_http(response, "Revocation discovery")
    metadata = object_body(response)
    try:
        url = httpx.URL(metadata.get("revocation_endpoint"))
    except (TypeError, httpx.InvalidURL):
        raise AppError("OpenAI's revocation endpoint is unavailable.") from None
    if (
        metadata.get("issuer") != ISSUER or url.scheme != "https" or url.host != "auth.openai.com"
        or url.port not in (None, 443) or url.userinfo or url.query or url.fragment
    ):
        raise AppError("OpenAI's revocation endpoint could not be verified.")
    for attempt in range(2):
        try:
            response = http.post(url, data={
                "token": refresh_token, "token_type_hint": "refresh_token", "client_id": client_id,
            })
        except httpx.RequestError:
            if attempt == 1:
                raise
        else:
            if response.status_code == 200:
                return
            if attempt == 1 or response.status_code < 500:
                check_http(response, "Session revocation")
                raise AppError("The revocation endpoint did not confirm success.")
        time.sleep(0.5)


def bearer(token):
    return {"Authorization": f"Bearer {token}"}
