from fastapi import FastAPI, HTTPException, Form, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
# from starlette.middleware.base import BaseHTTPMiddleware
from typing import Annotated, Union
import json
import requests
import urllib.parse


LAUNCHPAD_URL = "https://launchpad.net"
LAUNCHPAD_API = "https://api.launchpad.net"

app = FastAPI(
    title="Launchpad API Proxy",
    description="https://github.com/fourdollars/lp-api-proxy/",
    version="0.0.0",
    redoc_url='/',
    docs_url='/docs',
    openapi_url="/openapi.json",
    # root_path='/lp-api',
)

origins = ["*"]

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


@app.get("/devel/{api:path}", response_class=JSONResponse)
async def devel_get(
    request: Request, api: str, authorization: Union[str, None] = Header(default=None)
):
    headers = {}
    if authorization:
        headers["Authorization"] = authorization
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
    if authorization:
        headers["Authorization"] = authorization
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
    if authorization:
        headers["Authorization"] = authorization
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
    if authorization:
        headers["Authorization"] = authorization
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
