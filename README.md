# Launchpad API proxy

## Setup the service

```
$ git clone --depth=1 https://github.com/fourdollars/lp-api-proxy.git
$ cd lp-api-proxy
$ uv sync
$ uv run gunicorn main:app -k uvicorn.workers.UvicornWorker -b 0.0.0.0:3456 -w 4
```
