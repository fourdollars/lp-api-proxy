from fastapi import FastAPI, HTTPException, Form, Header, Request, Query
from fastapi.responses import (
    Response,
    PlainTextResponse,
    RedirectResponse,
    JSONResponse,
    HTMLResponse,
)
from os.path import exists
from pydantic import Required
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Union
import json
import requests
import urllib.parse


LAUNCHPAD_URL = "https://launchpad.net"
LAUNCHPAD_API = "https://api.launchpad.net"

app = FastAPI(
    title="Launchpad API Proxy",
    description="https://github.com/fourdollars/lp-api-proxy/",
    version="0.0.0",
    redoc_url="/",
    # docs_url=None,
)


@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request, exc):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.post("/+request-token", response_class=PlainTextResponse)
def request_token(
    oauth_consumer_key: str = Form(default=Required),
    oauth_signature_method: str = Form(default=Required),
    oauth_signature: str = Form(default=Required),
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
    oauth_token: str = Query(default=Required),
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
    oauth_token: str = Form(default=Required),
    oauth_consumer_key: str = Form(default=Required),
    oauth_signature_method: str = Form(default=Required),
    oauth_signature: str = Form(default=Required),
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


@app.get("/{file}")
async def read_root(file: str):
    if file == "" or not exists(f"public/{file}"):
        raise HTTPException(status_code=404)
    with open(f"public/{file}") as f:
        data = f.read()
    if file.endswith(".html"):
        return HTMLResponse(content=data, status_code=requests.codes.ok)
    elif file.endswith(".js"):
        return Response(
            content=data, status_code=requests.codes.ok, media_type="text/javascript"
        )
    raise HTTPException(status_code=404)
