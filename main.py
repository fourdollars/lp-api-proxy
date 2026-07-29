from fastapi import FastAPI, HTTPException, Form, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    PlainTextResponse,
    RedirectResponse,
    JSONResponse,
)
from starlette.exceptions import HTTPException as StarletteHTTPException

# from starlette.middleware.base import BaseHTTPMiddleware
from typing import Annotated, Optional, Union
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import warnings
import re

import jwt
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_gen
from cryptography.hazmat.primitives.serialization import load_pem_private_key

LAUNCHPAD_URL = "https://launchpad.net"
LAUNCHPAD_API = "https://api.launchpad.net"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# --- Launchpad OAuth 1.0a signing (used by the token exchange adapter) ----
#
# The proxy itself acts as an OAuth 1.0a *consumer* towards Launchpad, so it
# can drive the three-legged handshake (request-token -> user authorization
# -> access-token) on behalf of clients that only speak OAuth 2.0 / OIDC
# (e.g. Concourse CI). Launchpad doesn't hand out consumer secrets, so the
# signature is normally PLAINTEXT with an empty consumer secret, exactly
# like launchpadlib.
#
#   LP_CONSUMER_KEY       Consumer key the proxy identifies itself with to
#                          Launchpad (default: "lp-api-proxy").
#   LP_CONSUMER_SECRET    Consumer secret, usually blank for Launchpad.
#   LP_SIGNATURE_METHOD   "PLAINTEXT" (default) or "HMAC-SHA1".

LP_CONSUMER_KEY = os.environ.get("LP_CONSUMER_KEY", "lp-api-proxy")
LP_CONSUMER_SECRET = os.environ.get("LP_CONSUMER_SECRET", "")
LP_SIGNATURE_METHOD = os.environ.get("LP_SIGNATURE_METHOD", "PLAINTEXT")
PROXY_ALLOWED_ORIGINS = [
    item.strip().lower().rstrip("/")
    for item in os.environ.get("PROXY_ALLOWED_ORIGINS", "").split(",")
    if item.strip()
]
MAX_CONSUMER_KEY_LENGTH = 255


def _percent_encode(value):
    return urllib.parse.quote(str(value), safe="~")


def _origin_from_redirect_uri(redirect_uri):
    if not redirect_uri:
        return None
    try:
        parsed = urllib.parse.urlsplit(redirect_uri)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _normalize_consumer_key(value):
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    # Keep a conservative ASCII subset to avoid Launchpad-side parsing issues.
    text = re.sub(r"[^A-Za-z0-9 ._:/()\-]", "", text)
    return text[:MAX_CONSUMER_KEY_LENGTH] if text else LP_CONSUMER_KEY


def _dynamic_consumer_key(client_id, redirect_uri):
    origin = _origin_from_redirect_uri(redirect_uri)
    if not origin:
        return LP_CONSUMER_KEY

    base = (client_id or "").strip() or LP_CONSUMER_KEY
    return _normalize_consumer_key(f"{base} ({origin})")


def _require_allowed_origin(redirect_uri):
    origin = _origin_from_redirect_uri(redirect_uri)
    if not PROXY_ALLOWED_ORIGINS:
        return origin
    if not origin:
        raise HTTPException(
            status_code=400,
            detail="redirect_uri with an absolute origin is required",
        )
    if origin.lower().rstrip("/") not in PROXY_ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=403,
            detail="redirect_uri origin is not allowed by PROXY_ALLOWED_ORIGINS",
        )
    return origin


def _oauth1_hmac_sha1_signature(
    http_method, url, params, consumer_secret, token_secret
):
    parsed = urllib.parse.urlsplit(url)
    base_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, "", "")
    )
    normalized = "&".join(
        f"{_percent_encode(k)}={_percent_encode(v)}"
        for k, v in sorted(params.items())
        if k != "oauth_signature"
    )
    base_string = "&".join(
        [http_method.upper(), _percent_encode(base_url), _percent_encode(normalized)]
    )
    key = (
        _percent_encode(consumer_secret or "")
        + "&"
        + _percent_encode(token_secret or "")
    ).encode()
    digest = hmac.new(key, base_string.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def _oauth1_params(
    consumer_key,
    consumer_secret,
    token=None,
    token_secret=None,
    signature_method=LP_SIGNATURE_METHOD,
    http_method="GET",
    url=None,
    callback=None,
):
    """Return a dict of OAuth 1.0a parameters (including signature).
    Launchpad accepts these as form-body fields for its token endpoints,
    and as an Authorization header for regular API calls."""
    params = {
        "oauth_consumer_key": consumer_key,
        "oauth_signature_method": signature_method,
        "oauth_timestamp": str(int(time.time())),
        "oauth_nonce": secrets.token_hex(16),
        "oauth_version": "1.0",
    }
    if token:
        params["oauth_token"] = token
    if callback:
        params["oauth_callback"] = callback

    if signature_method == "PLAINTEXT":
        signature = (
            _percent_encode(consumer_secret or "")
            + "&"
            + _percent_encode(token_secret or "")
        )
    elif signature_method == "HMAC-SHA1":
        if not url:
            raise HTTPException(
                status_code=500, detail="HMAC-SHA1 signing requires a URL."
            )
        signature = _oauth1_hmac_sha1_signature(
            http_method, url, params, consumer_secret, token_secret
        )
    else:
        raise HTTPException(
            status_code=500,
            detail=f"Unsupported OAuth1 signature method: {signature_method}",
        )
    params["oauth_signature"] = signature
    return params


def _oauth1_authorization_header(
    consumer_key,
    consumer_secret,
    token=None,
    token_secret=None,
    signature_method=LP_SIGNATURE_METHOD,
    http_method="GET",
    url=None,
    callback=None,
):
    """Build a fresh OAuth 1.0a Authorization header (for regular API calls)."""
    params = _oauth1_params(
        consumer_key, consumer_secret, token, token_secret,
        signature_method, http_method, url, callback,
    )
    return "OAuth " + ", ".join(
        f'{k}="{_percent_encode(v)}"' for k, v in params.items()
    )


# --- Built-in OIDC Provider (Launchpad OAuth 1.0a backend) ---------------
#
# lp-api-proxy acts as a standards-compliant OIDC Provider for clients
# such as Concourse CI. Launchpad's OAuth 1.0a three-legged flow is the
# actual authentication mechanism; the proxy translates the result into
# standard OIDC tokens that Concourse can consume without ever knowing
# about OAuth 1.0a.
#
# Flow:
#  1. Concourse redirects user to /oauth2/login (authorization_endpoint).
#  2. Proxy drives the Launchpad OAuth 1.0a handshake (proxy = consumer).
#  3. After user approves on Launchpad, proxy fetches the user profile from
#     api.launchpad.net, issues a short-lived encrypted authorization "code"
#     containing LP credentials + user info, and redirects to redirect_uri?code=...
#  4. Concourse calls POST /oauth2/token and receives:
#       - id_token  (RS256 JWT) — Concourse verifies via /oauth2/jwks
#       - access_token (HS256 JWT) — carries encrypted LP credentials for /devel/*
#  5. Proxy stays 100%% stateless: all state travels encrypted in tokens.
#
# Required:
#   PROXY_JWT_SECRET          HMAC secret (≥32 bytes) for HS256 tokens.
#   PROXY_JWT_ENCRYPTION_KEY  Fernet key for encrypting LP credentials in JWTs.
#
# Optional:
#   PROXY_BASE_URL            Public base URL (default: http://localhost:3456).
#   PROXY_ALLOWED_ORIGINS     Comma-separated redirect_uri origins allowed for:
#                              1) CORS allow_origins
#                              2) dynamic Launchpad oauth_consumer_key naming
#   PROXY_RSA_PRIVATE_KEY     PEM RSA private key for RS256 id_tokens.
#                              Generate: openssl genrsa 2048
#                              Omitting generates an ephemeral key (not for production).
#   PROXY_OIDC_CLIENT_ID      client_id Concourse uses (default: "concourse-ci").
#   PROXY_OIDC_CLIENT_SECRET  client_secret for token endpoint (confidential clients).
#   PROXY_JWT_ISSUER          iss claim override (default: PROXY_BASE_URL).
#   PROXY_JWT_AUDIENCE        aud claim for access tokens (default: "concourse-ci").
#   PROXY_JWT_TTL_SECONDS     Access token lifetime (default: 2592000 = 30 days).
#   PROXY_CODE_TTL_SECONDS    Authorization code lifetime (default: 120 seconds).
#   LOGIN_SESSION_TTL_SECONDS Login session token lifetime (default: 600 seconds).

PROXY_BASE_URL = os.environ.get("PROXY_BASE_URL", "http://localhost:3456").rstrip("/")
PROXY_RSA_PRIVATE_KEY_PEM = os.environ.get("PROXY_RSA_PRIVATE_KEY")
PROXY_OIDC_CLIENT_ID = os.environ.get("PROXY_OIDC_CLIENT_ID", "concourse-ci")
PROXY_OIDC_CLIENT_SECRET = os.environ.get("PROXY_OIDC_CLIENT_SECRET")
PROXY_JWT_SECRET = os.environ.get("PROXY_JWT_SECRET")
PROXY_JWT_ENCRYPTION_KEY = os.environ.get("PROXY_JWT_ENCRYPTION_KEY")
PROXY_JWT_ISSUER = os.environ.get("PROXY_JWT_ISSUER") or PROXY_BASE_URL
PROXY_JWT_AUDIENCE = os.environ.get("PROXY_JWT_AUDIENCE", "concourse-ci")
PROXY_JWT_TTL_SECONDS = int(os.environ.get("PROXY_JWT_TTL_SECONDS", "2592000"))
PROXY_CODE_TTL_SECONDS = int(os.environ.get("PROXY_CODE_TTL_SECONDS", "120"))
LOGIN_SESSION_TTL_SECONDS = int(os.environ.get("LOGIN_SESSION_TTL_SECONDS", "600"))

# RSA key management

_rsa_private_key = None
_rsa_key_id = None


def _get_rsa_private_key():
    global _rsa_private_key, _rsa_key_id
    if _rsa_private_key is None:
        if PROXY_RSA_PRIVATE_KEY_PEM:
            _rsa_private_key = load_pem_private_key(
                PROXY_RSA_PRIVATE_KEY_PEM.encode(), password=None
            )
        else:
            warnings.warn(
                "PROXY_RSA_PRIVATE_KEY is not set — generating an ephemeral RSA key. "
                "Concourse will reject id_tokens after a proxy restart. "
                "Run: openssl genrsa 2048 and set PROXY_RSA_PRIVATE_KEY."
            )
            _rsa_private_key = _rsa_gen.generate_private_key(
                public_exponent=65537, key_size=2048
            )
        _rsa_key_id = secrets.token_hex(8)
    return _rsa_private_key, _rsa_key_id


def _int_to_base64url(n):
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def _jwks_document():
    priv, kid = _get_rsa_private_key()
    pub = priv.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _int_to_base64url(pub.n),
                "e": _int_to_base64url(pub.e),
            }
        ]
    }


def _sign_id_token(payload):
    priv, kid = _get_rsa_private_key()
    return jwt.encode(payload, priv, algorithm="RS256", headers={"kid": kid})


# HS256 helpers (internal sessions + access tokens)


def _require_jwt_secret():
    if not PROXY_JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Token exchange is not configured: PROXY_JWT_SECRET is required.",
        )
    return PROXY_JWT_SECRET


def _fernet():
    if not PROXY_JWT_ENCRYPTION_KEY:
        raise HTTPException(
            status_code=500,
            detail="Token exchange is not configured: PROXY_JWT_ENCRYPTION_KEY is required.",
        )
    try:
        return Fernet(PROXY_JWT_ENCRYPTION_KEY.encode())
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Invalid PROXY_JWT_ENCRYPTION_KEY: {exc}"
        )


def _sign_jwt(payload, ttl_seconds):
    now = int(time.time())
    claims = {**payload, "iss": PROXY_JWT_ISSUER, "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(claims, _require_jwt_secret(), algorithm="HS256")


def _verify_jwt(token, audience=None):
    try:
        return jwt.decode(
            token,
            _require_jwt_secret(),
            algorithms=["HS256"],
            audience=audience,
            options={"verify_aud": audience is not None},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {exc}")


# Launchpad user info


def _group_name_from_link(value):
    if not value or not isinstance(value, str):
        return None
    raw = value.strip().rstrip("/")
    if "/~" in raw:
        return raw.rsplit("/~", 1)[1].split("/", 1)[0]
    if raw.startswith("~"):
        return raw[1:].split("/", 1)[0]
    return None


def _group_full_url(name):
    if not name:
        return None
    return f"https://launchpad.net/~{name}"


def _extract_groups_from_membership_entry(entry):
    names = set()
    urls = set()
    if not isinstance(entry, dict):
        return names, urls

    for key in ("web_link", "self_link", "team_link"):
        value = entry.get(key)
        if isinstance(value, str):
            name = _group_name_from_link(value)
            if name:
                names.add(name)
                full = _group_full_url(name)
                if full:
                    urls.add(full)

    team = entry.get("team")
    if isinstance(team, dict):
        team_name = team.get("name")
        if team_name:
            names.add(str(team_name))
        for key in ("web_link", "self_link"):
            value = team.get(key)
            if isinstance(value, str):
                name = _group_name_from_link(value)
                if name:
                    names.add(name)
                    full = _group_full_url(name)
                    if full:
                        urls.add(full)

    name = entry.get("name")
    if isinstance(name, str) and name and " " not in name:
        names.add(name)
        full = _group_full_url(name)
        if full:
            urls.add(full)

    return names, urls


def _lp_fetch_groups(oauth_authorization_header, me_data):
    links = []
    for key in (
        "memberships_details_collection_link",
        "memberships_collection_link",
        "super_teams_collection_link",
        "team_memberships_collection_link",
    ):
        link = me_data.get(key)
        if isinstance(link, str) and link:
            links.append(link)

    group_names = set()
    group_urls = set()
    for link in dict.fromkeys(links):
        resp = requests.get(link, headers={"Authorization": oauth_authorization_header})
        if resp.status_code != requests.codes.ok:
            continue
        payload = resp.json()
        for entry in payload.get("entries", []):
            names, urls = _extract_groups_from_membership_entry(entry)
            group_names.update(names)
            group_urls.update(urls)

    return sorted(group_names), sorted(group_urls)


def _lp_fetch_me(oauth_token, oauth_token_secret, oauth_consumer_key):
    auth = _oauth1_authorization_header(
        oauth_consumer_key,
        LP_CONSUMER_SECRET,
        token=oauth_token,
        token_secret=oauth_token_secret,
        signature_method=LP_SIGNATURE_METHOD,
    )
    resp = requests.get(
        f"{LAUNCHPAD_API}/devel/people/+me",
        headers={"Authorization": auth},
    )
    if resp.status_code != requests.codes.ok:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to fetch Launchpad user info: {resp.text}",
        )
    data = resp.json()
    groups, groups_full = _lp_fetch_groups(auth, data)
    username = data.get("name", oauth_token)
    return {
        "sub": username,
        "username": username,
        "user_id": username,
        "name": data.get("display_name", data.get("name", "")),
        "profile": data.get(
            "web_link", f"https://launchpad.net/~{data.get('name', '')}"
        ),
        "groups": groups,
        "groups_full": groups_full,
    }


# Authorization header resolver (Bearer JWT -> OAuth 1.0a)


def _resolve_authorization_header(authorization):
    """Pass-through for raw OAuth 1.0a headers; translate Bearer JWT issued
    by /oauth2/token into a fresh OAuth 1.0a signed header."""
    if not authorization or not authorization.startswith("Bearer "):
        return authorization

    token = authorization[len("Bearer "):]
    if not PROXY_JWT_SECRET or token.count(".") != 2:
        return authorization

    claims = _verify_jwt(token, audience=PROXY_JWT_AUDIENCE)
    if claims.get("typ") != "lp-access" or "lp_cred" not in claims:
        raise HTTPException(status_code=401, detail="Not a valid Launchpad access token")

    cred = json.loads(_fernet().decrypt(claims["lp_cred"].encode()).decode())
    return _oauth1_authorization_header(
        cred.get("oauth_consumer_key", LP_CONSUMER_KEY),
        LP_CONSUMER_SECRET,
        token=cred["oauth_token"],
        token_secret=cred["oauth_token_secret"],
        signature_method=LP_SIGNATURE_METHOD,
    )


app = FastAPI(
    title="Launchpad API Proxy",
    description="https://github.com/fourdollars/lp-api-proxy/",
    version="0.0.0",
    redoc_url="/",
    docs_url="/docs",
    openapi_url="/openapi.json",
    # root_path='/lp-api',
)

origins = PROXY_ALLOWED_ORIGINS if PROXY_ALLOWED_ORIGINS else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "OPTIONS", "PATCH", "POST", "PUT"],
    allow_headers=["Authorization"],
)

# Workaround the stupid reverse proxy server issue from some hosting service.
# class PathCorrectionMiddleware(BaseHTTPMiddleware):
#     async def dispatch(self, request, call_next):
#         if request.url.path.startswith("//"):
#             request.scope["path"] = request.url.path[1:]
#         response = await call_next(request)
#         return response


# app.add_middleware(PathCorrectionMiddleware)


@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request, exc):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.get("/example.html", include_in_schema=False)
def example_html():
    """A small, dependency-free HTML/JS page for manually testing the
    Launchpad-backed OIDC provider flow (/oauth2/login + /oauth2/token)."""
    return FileResponse(os.path.join(STATIC_DIR, "example.html"))


@app.post("/+request-token", response_class=PlainTextResponse)
def request_token(
    oauth_consumer_key: Annotated[str, Form()],
    oauth_signature_method: Annotated[str, Form()],
    oauth_signature: Annotated[str, Form()],
):
    data = {
        "oauth_consumer_key": oauth_consumer_key,
        "oauth_signature_method": oauth_signature_method,
        "oauth_signature": oauth_signature,
    }

    response = requests.post(f"{LAUNCHPAD_URL}/+request-token", data=data)

    if response.status_code == requests.codes.ok:
        return response.text

    raise HTTPException(status_code=response.status_code, detail=response.text)


@app.get("/+authorize-token", response_class=RedirectResponse)
def authorize_token(
    oauth_token: Annotated[str, Query()],
    allow_permission: str = None,
    oauth_callback: str = None,
):
    params = {"oauth_token": oauth_token}

    if allow_permission:
        params["allow_permission"] = allow_permission

    if oauth_callback:
        params["oauth_callback"] = oauth_callback

    return f"{LAUNCHPAD_URL}/+authorize-token?" + urllib.parse.urlencode(params)


@app.post("/+access-token", response_class=PlainTextResponse)
def access_token(
    oauth_token: Annotated[str, Form()],
    oauth_consumer_key: Annotated[str, Form()],
    oauth_signature_method: Annotated[str, Form()],
    oauth_signature: Annotated[str, Form()],
):
    data = {
        "oauth_token": oauth_token,
        "oauth_consumer_key": oauth_consumer_key,
        "oauth_signature_method": oauth_signature_method,
        "oauth_signature": oauth_signature,
    }

    response = requests.post(f"{LAUNCHPAD_URL}/+access-token", data=data)
    if response.status_code == requests.codes.ok:
        return response.text

    raise HTTPException(status_code=response.status_code, detail=response.text)


# --- Built-in OIDC Provider endpoints (Launchpad backend) -----------------


@app.get("/.well-known/openid-configuration", response_class=JSONResponse)
def oidc_provider_discovery():
    """Standard OIDC discovery document. Point Concourse at this proxy by
    setting the OIDC connector issuer to PROXY_BASE_URL."""
    base = PROXY_BASE_URL
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth2/login",
        "token_endpoint": f"{base}/oauth2/token",
        "userinfo_endpoint": f"{base}/oauth2/userinfo",
        "jwks_uri": f"{base}/oauth2/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "claims_supported": [
            "sub",
            "username",
            "user_id",
            "name",
            "profile",
            "groups",
            "groups_full",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
        ],
        "code_challenge_methods_supported": ["S256"],
    }


@app.get("/oauth2/jwks", response_class=JSONResponse)
def launchpad_jwks():
    """JWKS endpoint — Concourse fetches this to verify id_token RS256 signatures."""
    return _jwks_document()


@app.get("/oauth2/login")
def oauth2_launchpad_login(
    request: Request,
    response_type: str = "code",
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    state: Optional[str] = None,
    nonce: Optional[str] = None,
    scope: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
):
    """OIDC authorization endpoint — kicks off the Launchpad OAuth 1.0a
    three-legged flow on behalf of the client. The proxy is the
    OAuth 1.0a consumer; callers only need to speak standard OIDC."""
    _require_jwt_secret()
    _fernet()
    _require_allowed_origin(redirect_uri)
    oauth_consumer_key = _dynamic_consumer_key(client_id, redirect_uri)

    request_token_data = _oauth1_params(
        oauth_consumer_key,
        LP_CONSUMER_SECRET,
        signature_method=LP_SIGNATURE_METHOD,
        http_method="POST",
        url=f"{LAUNCHPAD_URL}/+request-token",
        callback=None,
    )
    response = requests.post(
        f"{LAUNCHPAD_URL}/+request-token",
        data=request_token_data,
    )
    if response.status_code != requests.codes.ok:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    req = dict(urllib.parse.parse_qsl(response.text))
    req_token = req.get("oauth_token")
    req_token_secret = req.get("oauth_token_secret")
    if not req_token or not req_token_secret:
        raise HTTPException(
            status_code=502,
            detail=f"Unexpected response from Launchpad +request-token: {response.text}",
        )

    session_token = _sign_jwt(
        {
            "typ": "lp-login-session",
            "req_token": req_token,
            "req_token_secret": req_token_secret,
            "oauth_consumer_key": oauth_consumer_key,
            "client_id": client_id or PROXY_OIDC_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        },
        LOGIN_SESSION_TTL_SECONDS,
    )
    callback_url = (
        str(request.base_url).rstrip("/")
        + "/oauth2/callback?"
        + urllib.parse.urlencode({"session": session_token})
    )
    params = {"oauth_token": req_token, "oauth_callback": callback_url}
    return RedirectResponse(
        f"{LAUNCHPAD_URL}/+authorize-token?" + urllib.parse.urlencode(params)
    )


@app.get("/oauth2/callback")
def oauth2_launchpad_callback(
    session: Annotated[str, Query()],
    oauth_token: Annotated[str | None, Query()] = None,
):
    """Completes the Launchpad OAuth 1.0a handshake, fetches the user
    profile, then issues a short-lived encrypted authorization code and
    redirects to the client's redirect_uri."""
    claims = _verify_jwt(session)
    if claims.get("typ") != "lp-login-session":
        raise HTTPException(status_code=400, detail="Invalid login session token")
    # Launchpad does not always append oauth_token to the callback URL;
    # fall back to the req_token stored in the session JWT.
    if oauth_token is None:
        oauth_token = claims.get("req_token")
    elif claims.get("req_token") != oauth_token:
        raise HTTPException(
            status_code=400, detail="oauth_token does not match the login session"
        )
    oauth_consumer_key = claims.get("oauth_consumer_key", LP_CONSUMER_KEY)

    access_token_data = _oauth1_params(
        oauth_consumer_key,
        LP_CONSUMER_SECRET,
        token=oauth_token,
        token_secret=claims["req_token_secret"],
        signature_method=LP_SIGNATURE_METHOD,
        http_method="POST",
        url=f"{LAUNCHPAD_URL}/+access-token",
    )
    response = requests.post(
        f"{LAUNCHPAD_URL}/+access-token", data=access_token_data
    )
    if response.status_code != requests.codes.ok:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    access = dict(urllib.parse.parse_qsl(response.text))
    lp_token = access.get("oauth_token")
    lp_token_secret = access.get("oauth_token_secret")
    if not lp_token or not lp_token_secret:
        raise HTTPException(
            status_code=502,
            detail=f"Unexpected response from Launchpad +access-token: {response.text}",
        )

    user = _lp_fetch_me(lp_token, lp_token_secret, oauth_consumer_key)

    encrypted_cred = (
        _fernet()
        .encrypt(
            json.dumps(
                {
                    "oauth_token": lp_token,
                    "oauth_token_secret": lp_token_secret,
                    "oauth_consumer_key": oauth_consumer_key,
                }
            ).encode()
        )
        .decode()
    )

    code = _sign_jwt(
        {
            "typ": "lp-code",
            "client_id": claims.get("client_id", PROXY_OIDC_CLIENT_ID),
            "redirect_uri": claims.get("redirect_uri"),
            "nonce": claims.get("nonce"),
            "scope": claims.get("scope", "openid profile"),
            "code_challenge": claims.get("code_challenge"),
            "code_challenge_method": claims.get("code_challenge_method"),
            "lp_cred": encrypted_cred,
            "user": user,
        },
        PROXY_CODE_TTL_SECONDS,
    )

    redirect_uri = claims.get("redirect_uri")
    if redirect_uri:
        params = {"code": code}
        if claims.get("state"):
            params["state"] = claims["state"]
        return RedirectResponse(redirect_uri + "?" + urllib.parse.urlencode(params))

    return JSONResponse({"code": code})


@app.post("/oauth2/token", response_class=JSONResponse)
def oauth2_launchpad_token(
    grant_type: Annotated[str, Form()],
    code: Annotated[Optional[str], Form()] = None,
    redirect_uri: Annotated[Optional[str], Form()] = None,
    client_id: Annotated[Optional[str], Form()] = None,
    client_secret: Annotated[Optional[str], Form()] = None,
    code_verifier: Annotated[Optional[str], Form()] = None,
):
    """OIDC token endpoint. Concourse calls this (server-to-server) to
    exchange the authorization code for id_token + access_token."""
    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=400, detail=f"Unsupported grant_type: {grant_type}"
        )
    if not code:
        raise HTTPException(status_code=400, detail="code is required")

    # Authenticate the client
    effective_client_id = client_id or PROXY_OIDC_CLIENT_ID
    if client_secret is not None:
        if not PROXY_OIDC_CLIENT_SECRET or client_secret != PROXY_OIDC_CLIENT_SECRET:
            raise HTTPException(status_code=401, detail="Invalid client_secret")
    elif not code_verifier:
        # If no client_secret is supplied, require PKCE.
        raise HTTPException(
            status_code=401,
            detail="Either a valid client_secret or a code_verifier must be provided",
        )

    code_claims = _verify_jwt(code)
    if code_claims.get("typ") != "lp-code":
        raise HTTPException(status_code=400, detail="Invalid authorization code")

    # Validate client binding
    if code_claims.get("client_id") != effective_client_id:
        raise HTTPException(status_code=400, detail="client_id mismatch")
    if code_claims.get("redirect_uri") and code_claims["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri mismatch")

    # Verify PKCE if code_challenge was stored
    if code_claims.get("code_challenge"):
        if not code_verifier:
            raise HTTPException(
                status_code=400, detail="code_verifier required (PKCE)"
            )
        import hashlib as _hl
        digest = base64.urlsafe_b64encode(
            _hl.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if digest != code_claims["code_challenge"]:
            raise HTTPException(status_code=400, detail="code_verifier mismatch")

    user = code_claims["user"]
    now = int(time.time())

    id_token = _sign_id_token(
        {
            "iss": PROXY_JWT_ISSUER,
            "aud": effective_client_id,
            "sub": user["sub"],
            "username": user.get("username", user["sub"]),
            "user_id": user.get("user_id", user["sub"]),
            "name": user["name"],
            "profile": user["profile"],
            "groups": user.get("groups", []),
            "groups_full": user.get("groups_full", []),
            "iat": now,
            "exp": now + PROXY_JWT_TTL_SECONDS,
            **({"nonce": code_claims["nonce"]} if code_claims.get("nonce") else {}),
        }
    )

    access_token = _sign_jwt(
        {
            "typ": "lp-access",
            "aud": PROXY_JWT_AUDIENCE,
            "sub": user["sub"],
            "username": user.get("username", user["sub"]),
            "user_id": user.get("user_id", user["sub"]),
            "name": user["name"],
            "profile": user["profile"],
            "groups": user.get("groups", []),
            "groups_full": user.get("groups_full", []),
            "lp_cred": code_claims["lp_cred"],
        },
        PROXY_JWT_TTL_SECONDS,
    )

    return {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "bearer",
        "expires_in": PROXY_JWT_TTL_SECONDS,
    }


@app.get("/oauth2/userinfo", response_class=JSONResponse)
def oauth2_launchpad_userinfo(
    authorization: Union[str, None] = Header(default=None),
):
    """OIDC userinfo endpoint — returns the user profile embedded in the
    access_token issued by /oauth2/token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization[len("Bearer "):]
    claims = _verify_jwt(token, audience=PROXY_JWT_AUDIENCE)
    if claims.get("typ") != "lp-access":
        raise HTTPException(status_code=401, detail="Not a valid Launchpad access token")
    return {
        "sub": claims.get("sub"),
        "username": claims.get("username", claims.get("sub")),
        "user_id": claims.get("user_id", claims.get("sub")),
        "name": claims.get("name"),
        "profile": claims.get("profile"),
        "groups": claims.get("groups", []),
        "groups_full": claims.get("groups_full", []),
    }


@app.get("/devel/{api:path}", response_class=JSONResponse)
async def devel_get(
    request: Request, api: str, authorization: Union[str, None] = Header(default=None)
):
    headers = {}
    resolved_authorization = _resolve_authorization_header(authorization)
    if resolved_authorization:
        headers["Authorization"] = resolved_authorization
    response = requests.get(
        f"{LAUNCHPAD_API}/devel/{api}", headers=headers, params=request.query_params
    )
    if response.status_code == requests.codes.ok:
        return json.loads(response.text)
    raise HTTPException(status_code=response.status_code, detail=response.text)


@app.post("/devel/{api:path}", response_class=JSONResponse)
async def devel_post(
    request: Request, api: str, authorization: Union[str, None] = Header(default=None)
):
    headers = {}
    resolved_authorization = _resolve_authorization_header(authorization)
    if resolved_authorization:
        headers["Authorization"] = resolved_authorization
    payload = await request.form()
    response = requests.post(
        f"{LAUNCHPAD_API}/devel/{api}",
        headers=headers,
        params=request.query_params,
        data=payload,
    )
    if response.status_code == requests.codes.ok:
        return json.loads(response.text)
    raise HTTPException(status_code=response.status_code, detail=response.text)


@app.patch("/devel/{api:path}", response_class=JSONResponse)
async def devel_patch(
    request: Request, api: str, authorization: Union[str, None] = Header(default=None)
):
    headers = {}
    resolved_authorization = _resolve_authorization_header(authorization)
    if resolved_authorization:
        headers["Authorization"] = resolved_authorization
    payload = await request.json()
    response = requests.patch(
        f"{LAUNCHPAD_API}/devel/{api}",
        headers=headers,
        params=request.query_params,
        data=json.dumps(payload),
    )
    if response.status_code == requests.codes.ok:
        return json.loads(response.text)
    raise HTTPException(status_code=response.status_code, detail=response.text)


@app.put("/devel/{api:path}", response_class=JSONResponse)
async def devel_put(
    request: Request, api: str, authorization: Union[str, None] = Header(default=None)
):
    headers = {}
    resolved_authorization = _resolve_authorization_header(authorization)
    if resolved_authorization:
        headers["Authorization"] = resolved_authorization
    payload = await request.json()
    response = requests.put(
        f"{LAUNCHPAD_API}/devel/{api}",
        headers=headers,
        params=request.query_params,
        data=json.dumps(payload),
    )
    if response.status_code == requests.codes.ok:
        return json.loads(response.text)
    raise HTTPException(status_code=response.status_code, detail=response.text)
