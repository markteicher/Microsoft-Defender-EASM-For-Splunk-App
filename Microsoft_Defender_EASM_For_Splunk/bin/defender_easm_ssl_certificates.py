#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
bin/defender_easm_ssl_certificates.py

Microsoft Defender EASM for Splunk App
Modular Input: SSL Certificates

- Uses Defender EASM data-plane API
- OAuth2 client-credentials (via defender_easm_common.py)
- Paginates using nextLink (checkpointed)
- Writes raw JSON events (one per object) to Splunk

Sourcetype (recommended): defender:easm:ssl_certificate
Input stanza name in inputs.conf: [defender_easm_ssl_certificates]
"""

import json
import time
from typing import Any, Dict, Iterable, Optional, Tuple

import requests

from splunklib.modularinput import Script, EventWriter, Event

from defender_easm_common import (
    APP_NAME,
    get_access_token,
    get_headers,
    get_easm_base_url,
    get_proxy_config,
    get_checkpoint,
    save_checkpoint,
)

# API version: keep configurable if needed later
DEFAULT_API_VERSION = "2024-10-01-preview"


class DefenderEASMSslCertificates(Script):
    def get_scheme(self):
        scheme = super().get_scheme()
        scheme.title = "Microsoft Defender EASM - SSL Certificates"
        scheme.description = "Collects SSL certificate assets from Defender EASM data-plane."
        scheme.use_external_validation = True
        return scheme

    def _build_first_url(self, session_key: str) -> str:
        base = get_easm_base_url(session_key)
        # Data-plane list for SSL certificates
        # Convention matches other assets collections: /sslCertificates
        return f"{base}/sslCertificates?api-version={DEFAULT_API_VERSION}"

    def _iter_pages(
        self,
        session_key: str,
        start_url: str,
        checkpoint_key: str,
        timeout: int = 120,
    ) -> Iterable[Tuple[str, Dict[str, Any]]]:
        """
        Yields (url, json_payload) for each page.
        Uses nextLink when present.
        """
        proxies = get_proxy_config(session_key)
        token = get_access_token(session_key)
        headers = get_headers(token)

        # Resume from checkpoint if present
        resume_url = get_checkpoint(checkpoint_key)
        url = resume_url if resume_url else start_url

        while url:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            resp.raise_for_status()
            payload = resp.json()

            yield url, payload

            # Prefer common patterns
            next_link = payload.get("nextLink") or payload.get("@odata.nextLink")
            if next_link:
                save_checkpoint(checkpoint_key, next_link)
                url = next_link
            else:
                save_checkpoint(checkpoint_key, None)
                url = None

    def _extract_items(self, payload: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        """
        Defender EASM list payloads are typically { "value": [ ... ], "nextLink": "..." }.
        """
        items = payload.get("value")
        if isinstance(items, list):
            for obj in items:
                if isinstance(obj, dict):
                    yield obj

    def stream_events(self, inputs, ew: EventWriter):
        # Splunk passes session key in inputs.metadata
        session_key = inputs.metadata.get("session_key")
        if not session_key:
            raise RuntimeError("Missing Splunk session_key in modular input metadata.")

        # Only run enabled stanzas
        for stanza_name, stanza in inputs.inputs.items():
            if stanza_name != "defender_easm_ssl_certificates":
                continue

            index = stanza.get("index", "security_defender_easm")
            sourcetype = stanza.get("sourcetype", "defender:easm:ssl_certificate")

            checkpoint_key = f"{APP_NAME}::ssl_certificates::{stanza_name}"
            first_url = self._build_first_url(session_key)

            for _, page in self._iter_pages(session_key, first_url, checkpoint_key):
                for obj in self._extract_items(page):
                    # Preserve raw payload; add light metadata fields only if absent
                    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

                    ew.write_event(
                        Event(
                            data=raw,
                            sourcetype=sourcetype,
                            index=index,
                        )
                    )


if __name__ == "__main__":
    DefenderEASMSslCertificates().run()
