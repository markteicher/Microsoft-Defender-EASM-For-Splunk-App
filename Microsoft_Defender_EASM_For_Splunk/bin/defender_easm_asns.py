#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: ASNs

API:
GET /assets/asns

Production guarantees:
- Azure AD OAuth2 authentication
- Pagination via nextLink
- Checkpointing (cursor-safe)
- Proxy support (with or without auth)
- Retries + backoff
- One JSON event per ASN
- Splunk Cloud & AppInspect compliant
"""

import json
import time
import requests
import splunklib.modularinput as smi

from defender_easm_common import (
    get_access_token,
    get_easm_base_url,
    get_headers,
    get_proxy_config,
    get_checkpoint,
    save_checkpoint,
)

SOURCETYPE = "defender:easm:asn"
CHECKPOINT_KEY = "defender_easm_asns_nextlink"


class DefenderEASMAsnsInput(smi.Script):

    def get_scheme(self):
        scheme = smi.Scheme("Defender EASM ASNs")
        scheme.description = "Collect ASN assets from Microsoft Defender EASM"
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = False
        return scheme

    def stream_events(self, inputs, ew):
        stanza_name = list(inputs.keys())[0]
        session_key = self._input_definition.metadata["session_key"]

        base_url = get_easm_base_url(session_key)
        token = get_access_token(session_key)
        headers = get_headers(token)
        proxies = get_proxy_config(session_key)

        # Restore pagination checkpoint
        next_link = get_checkpoint(CHECKPOINT_KEY) or (
            f"{base_url}/assets/asns?api-version=2024-10-01-preview"
        )

        while next_link:
            response = self._safe_request(
                url=next_link,
                headers=headers,
                proxies=proxies
            )

            payload = response.json()

            for asn in payload.get("value", []):
                event = smi.Event()
                event.stanza = stanza_name
                event.sourcetype = SOURCETYPE
                event.data = json.dumps(asn)
                ew.write_event(event)

            next_link = payload.get("nextLink")
            save_checkpoint(CHECKPOINT_KEY, next_link)

    def _safe_request(self, url, headers, proxies, retries=5):
        for attempt in range(1, retries + 1):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    proxies=proxies,
                    timeout=60
                )
                response.raise_for_status()
                return response
            except Exception as e:
                if attempt == retries:
                    raise
                time.sleep(attempt * 2)


if __name__ == "__main__":
    smi.Script.run(DefenderEASMAsnsInput)
