#!/usr/bin/env bash
set -euo pipefail

CHARM_DIR="${JUJU_CHARM_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
APP_DIR="${CHARM_DIR}"
VENV_DIR="/var/lib/lp-api-proxy/venv"
STATE_DIR="/var/lib/lp-api-proxy"
STATE_FILE="${STATE_DIR}/generated-secrets.env"
ENV_FILE="/etc/lp-api-proxy.env"
SERVICE_FILE="/etc/systemd/system/lp-api-proxy.service"

config() {
  config-get "$1"
}

apply_proxy_env() {
  local http_proxy https_proxy no_proxy
  http_proxy="$(config http-proxy)"
  https_proxy="$(config https-proxy)"
  no_proxy="$(config no-proxy)"

  if [[ -n "${http_proxy}" ]]; then
    export HTTP_PROXY="${http_proxy}"
    export http_proxy="${http_proxy}"
  fi
  if [[ -n "${https_proxy}" ]]; then
    export HTTPS_PROXY="${https_proxy}"
    export https_proxy="${https_proxy}"
  fi
  if [[ -n "${no_proxy}" ]]; then
    export NO_PROXY="${no_proxy}"
    export no_proxy="${no_proxy}"
  fi
}

effective_base_url() {
  local base_url listen_port private_addr
  base_url="$(config proxy-base-url)"
  listen_port="$(to_int_string "$(config listen-port)")"
  if [[ -z "${base_url}" ]]; then
    private_addr="$(unit-get private-address)"
    base_url="http://${private_addr}:${listen_port}"
  fi
  echo "${base_url}"
}

to_int_string() {
  python3 - "$1" <<'PY'
import sys
value = sys.argv[1].strip()
print(int(float(value)))
PY
}

ensure_state_dir() {
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"
}

generate_defaults_if_missing() {
  ensure_state_dir
  if [[ ! -f "${STATE_FILE}" ]]; then
    cat >"${STATE_FILE}" <<'EOF'
PROXY_JWT_SECRET=
PROXY_JWT_ENCRYPTION_KEY=
EOF
    chmod 600 "${STATE_FILE}"
  fi

  # shellcheck disable=SC1090
  source "${STATE_FILE}"

  if [[ -z "${PROXY_JWT_SECRET}" ]]; then
    PROXY_JWT_SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  fi

  if [[ -z "${PROXY_JWT_ENCRYPTION_KEY}" ]]; then
    PROXY_JWT_ENCRYPTION_KEY="$(python3 - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
  fi

  cat >"${STATE_FILE}" <<EOF
PROXY_JWT_SECRET=${PROXY_JWT_SECRET}
PROXY_JWT_ENCRYPTION_KEY=${PROXY_JWT_ENCRYPTION_KEY}
EOF
  chmod 600 "${STATE_FILE}"
}

ensure_runtime() {
  apply_proxy_env
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv

  mkdir -p "${VENV_DIR}"
  if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi

  "${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt"
}

write_env_file() {
  generate_defaults_if_missing
  # shellcheck disable=SC1090
  source "${STATE_FILE}"

  local listen_host listen_port base_url
  listen_host="$(config listen-host)"
  listen_port="$(to_int_string "$(config listen-port)")"
  base_url="$(effective_base_url)"

  local client_id client_secret jwt_secret jwt_key jwt_issuer jwt_aud jwt_ttl code_ttl session_ttl
  local http_proxy https_proxy no_proxy
  client_id="$(config proxy-oidc-client-id)"
  client_secret="$(config proxy-oidc-client-secret)"
  jwt_secret="$(config proxy-jwt-secret)"
  jwt_key="$(config proxy-jwt-encryption-key)"
  jwt_issuer="$(config proxy-jwt-issuer)"
  jwt_aud="$(config proxy-jwt-audience)"
  jwt_ttl="$(to_int_string "$(config proxy-jwt-ttl-seconds)")"
  code_ttl="$(to_int_string "$(config proxy-code-ttl-seconds)")"
  session_ttl="$(to_int_string "$(config login-session-ttl-seconds)")"
  http_proxy="$(config http-proxy)"
  https_proxy="$(config https-proxy)"
  no_proxy="$(config no-proxy)"

  if [[ -z "${jwt_secret}" ]]; then
    jwt_secret="${PROXY_JWT_SECRET}"
  fi
  if [[ -z "${jwt_key}" ]]; then
    jwt_key="${PROXY_JWT_ENCRYPTION_KEY}"
  fi

  cat >"${ENV_FILE}" <<EOF
PROXY_BASE_URL=${base_url}
PROXY_OIDC_CLIENT_ID=${client_id}
PROXY_OIDC_CLIENT_SECRET=${client_secret}
PROXY_JWT_SECRET=${jwt_secret}
PROXY_JWT_ENCRYPTION_KEY=${jwt_key}
PROXY_JWT_ISSUER=${jwt_issuer}
PROXY_JWT_AUDIENCE=${jwt_aud}
PROXY_JWT_TTL_SECONDS=${jwt_ttl}
PROXY_CODE_TTL_SECONDS=${code_ttl}
LOGIN_SESSION_TTL_SECONDS=${session_ttl}
HTTP_PROXY=${http_proxy}
HTTPS_PROXY=${https_proxy}
NO_PROXY=${no_proxy}
http_proxy=${http_proxy}
https_proxy=${https_proxy}
no_proxy=${no_proxy}
LP_CONSUMER_KEY=lp-api-proxy
LP_CONSUMER_SECRET=
LP_SIGNATURE_METHOD=PLAINTEXT
EOF
  chmod 600 "${ENV_FILE}"
}

write_service_file() {
  local listen_host listen_port
  listen_host="$(config listen-host)"
  listen_port="$(to_int_string "$(config listen-port)")"

  cat >"${SERVICE_FILE}" <<EOF
[Unit]
Description=lp-api-proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/uvicorn main:app --host ${listen_host} --port ${listen_port}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

reload_and_restart_service() {
  local listen_port
  listen_port="$(to_int_string "$(config listen-port)")"
  systemctl daemon-reload
  systemctl enable lp-api-proxy.service
  systemctl restart lp-api-proxy.service
  open-port "${listen_port}/tcp"
}

stop_service() {
  local listen_port
  listen_port="$(to_int_string "$(config listen-port)")"
  systemctl stop lp-api-proxy.service || true
  systemctl disable lp-api-proxy.service || true
  close-port "${listen_port}/tcp" || true
}
