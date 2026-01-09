#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
bin/defender_easm_common.py

Microsoft Defender EASM for Splunk App
Shared helpers for all modular inputs.

Includes:
- Config read (supports multiple possible conf locations)
- Secure password retrieval (storage/passwords)
- Azure AD OAuth2 client-credentials token
- Data-plane base URL builder (configurable / future-proof)
- Requests headers + proxy support (with or without auth)
- File-based checkpointing (Splunk Cloud safe)
"""

import os
import json
import time
import base64
import hashlib
from typing import Any, Dict, Optional

import requests
import splunk.rest as splunk_rest

APP_NAME = "Microsoft_Defender_EASM_For_Splunk"

# Preferred: a dedicated conf for this app's setup values
CONF_PRIMARY = "defender_easm"
STANZA_PRIMARY = "settings"

# Back-compat fallback: some handlers save into conf-app using APP_NAME stanza
CONF_FALLBACK = "app"
STANZA_FALLBACK = APP_NAME

# Password storage naming convention
# We will look for usernames like:
#   defender_easm:client_secret
#   defender_easm:proxy_password
PASSWORD_PREFIX = "defender_easm:"


# ----------------------------
# REST helpers (Splunkd)
# ----------------------------

def _splunk_get_json(path: str, session_key: str) -> Dict[str, Any]:
    """
    GET splunkd endpoint returning JSON.
    """
    resp, content = splunk_rest.simpleRequest(
        path,
        sessionKey=session_key,
        method="GET",
        getargs={"output_mode": "json"},
        raiseAllErrors=True
    )
    return json.loads(content)


def _splunk_post(path: str, session_key: str, postargs: Dict[str, Any]) -> Dict[str, Any]:
    """
    POST splunkd endpoint returning JSON.
    """
    resp, content = splunk_rest.simpleRequest(
        path,
        sessionKey=session_key,
        method="POST",
        postargs=postargs,
        getargs={"output_mode": "json"},
        raiseAllErrors=True
    )
    return json.loads(content)


# ----------------------------
# Config / Secrets
# ----------------------------

def get_app_config(session_key: str) -> Dict[str, str]:
    """
    Reads setup/config values from Splunk conf.

    Primary:
      /servicesNS/nobody/<APP>/configs/conf-defender_easm/settings

    Fallback:
      /servicesNS/nobody/<APP>/configs/conf-app/<APP_NAME>

    Returns a flat dict of string values.
    """
    # Primary location
    primary_path = f"/servicesNS/nobody/{APP_NAME}/configs/conf-{CONF_PRIMARY}/{STANZA_PRIMARY}"
    try:
        data = _splunk_get_json(primary_path, session_key)
        entry = (data.get("entry") or [])[0]
        content = entry.get("content") or {}
        return {k: str(v) for k, v in content.items()}
    except Exception:
        pass

    # Fallback location
    fallback_path = f"/servicesNS/nobody/{APP_NAME}/configs/conf-{CONF_FALLBACK}/{STANZA_FALLBACK}"
    try:
        data = _splunk_get_json(fallback_path, session_key)
        entry = (data.get("entry") or [])[0]
        content = entry.get("content") or {}
        return {k: str(v) for k, v in content.items()}
    except Exception:
        return {}


def _get_stored_password(session_key: str, logical_name: str) -> Optional[str]:
    """
    Retrieves a secret from storage/passwords.

    We search for a credential with:
      username == "defender_easm:<logical_name>"

    Returns the clear-text password if found, else None.
    """
    username_match = f"{PASSWORD_PREFIX}{logical_name}"

    # List all passwords for the app context
    data = _splunk_get_json(f"/servicesNS/nobody/{APP_NAME}/storage/passwords", session_key)
    for entry in data.get("entry", []) or []:
        content = entry.get("content") or {}
        username = content.get("username")
        if username == username_match:
            # Splunk returns clear password in "clear_password" for GET storage/passwords entries (when allowed)
            clear_pw = content.get("clear_password")
            if clear_pw:
                return str(clear_pw)

    return None


def get_client_secret(session_key: str) -> str:
    secret = _get_stored_password(session_key, "client_secret")
    if not secret:
        raise RuntimeError("Missing client_secret in storage/passwords (expected username defender_easm:client_secret).")
    return secret


def get_proxy_password(session_key: str) -> Optional[str]:
    return _get_stored_password(session_key, "proxy_password")


# ----------------------------
# Azure AD OAuth2
# ----------------------------

def get_access_token(session_key: str) -> str:
    """
    Azure AD client-credentials flow.
    Uses:
      tenant_id, client_id, authority_url
    Secret:
      client_secret (storage/passwords)

    Scope:
      configurable via config key "scope"
      default: https://api.easm.defender.microsoft.com/.default
    """
    cfg = get_app_config(session_key)

    tenant_id = (cfg.get("tenant_id") or "").strip()
    client_id = (cfg.get("client_id") or "").strip()
    authority_url = (cfg.get("authority_url") or "https://login.microsoftonline.com").strip()
    scope = (cfg.get("scope") or "https://api.easm.defender.microsoft.com/.default").strip()

    if not tenant_id or not client_id:
        raise RuntimeError("Missing tenant_id or client_id in app configuration.")

    client_secret = get_client_secret(session_key)

    token_url = f"{authority_url.rstrip('/')}/{tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }

    proxies = get_proxy_config(session_key)

    resp = requests.post(token_url, data=data, proxies=proxies, timeout=60)
    resp.raise_for_status()
    payload = resp.json()

    token = payload.get("access_token")
    if not token:
        raise RuntimeError(f"Token response missing access_token: {payload}")
    return token


def get_headers(access_token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


# ----------------------------
# Data-plane base URL
# ----------------------------

def get_easm_base_url(session_key: str) -> str:
    """
    Returns the *data-plane* base URL for Defender EASM.

    Preferred config key:
      data_plane_endpoint

    Defaults to:
      https://api.easm.defender.microsoft.com

    Then constructs:
      {endpoint}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Easm/workspaces/{workspace_name}

    You can override the full base with:
      easm_base_url
    """
    cfg = get_app_config(session_key)

    explicit_base = (cfg.get("easm_base_url") or "").strip()
    if explicit_base:
        return explicit_base.rstrip("/")

    endpoint = (cfg.get("data_plane_endpoint") or "https://api.easm.defender.microsoft.com").strip().rstrip("/")

    subscription_id = (cfg.get("subscription_id") or "").strip()
    resource_group = (cfg.get("resource_group") or "").strip()
    workspace_name = (cfg.get("workspace_name") or "").strip()

    if not subscription_id or not resource_group or not workspace_name:
        raise RuntimeError("Missing subscription_id, resource_group, or workspace_name in app configuration.")

    return (
        f"{endpoint}"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Easm"
        f"/workspaces/{workspace_name}"
    )


# ----------------------------
# Proxy support
# ----------------------------

def get_proxy_config(session_key: str) -> Optional[Dict[str, str]]:
    """
    Returns a requests-compatible proxies dict or None.

    Supports:
      - proxy_url only  (no auth)
      - proxy_url + proxy_username (+ proxy_password) (basic auth)
    """
    cfg = get_app_config(session_key)

    use_proxy = (cfg.get("use_proxy") or "").strip().lower() in ("1", "true", "yes", "on")
    if not use_proxy:
        return None

    proxy_url = (cfg.get("proxy_url") or "").strip()
    if not proxy_url:
        return None

    proxy_username = (cfg.get("proxy_username") or "").strip()
    proxy_password = get_proxy_password(session_key) if proxy_username else None

    # If username provided but no password, still allow (some proxies accept username-only or NTLM frontends)
    if proxy_username:
        # Embed basic auth in URL safely
        # e.g. http://user:pass@proxy:8080
        from urllib.parse import urlparse, urlunparse, quote

        parsed = urlparse(proxy_url)
        netloc = parsed.netloc

        # If proxy_url already includes creds, do not double-embed
        if "@" not in netloc:
            user = quote(proxy_username, safe="")
            if proxy_password is not None:
                pw = quote(proxy_password, safe="")
                auth = f"{user}:{pw}"
            else:
                auth = f"{user}"
            netloc = f"{auth}@{netloc}"
            proxy_url = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    return {
        "http": proxy_url,
        "https": proxy_url,
    }


# ----------------------------
# Checkpointing (file-based)
# ----------------------------

def _checkpoint_dir() -> str:
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    path = os.path.join(splunk_home, "var", "lib", "splunk", "modinputs", APP_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _checkpoint_path(key: str) -> str:
    # Make filename stable/safe even if key has weird characters
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return os.path.join(_checkpoint_dir(), f"{h}.json")


def get_checkpoint(key: str) -> Optional[str]:
    """
    Returns stored checkpoint string (e.g., nextLink) or None.
    """
    path = _checkpoint_path(key)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj.get("value")
    except Exception:
        return None


def save_checkpoint(key: str, value: Optional[str]) -> None:
    """
    Saves checkpoint string. If value is None/empty, clears checkpoint.
    """
    path = _checkpoint_path(key)
    if not value:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return

    obj = {"value": value, "updated": int(time.time())}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)
