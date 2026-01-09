#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: Domains

Collects domain inventory from Microsoft Defender External Attack Surface Management.

Design principles:
- Single responsibility
- Deterministic execution
- Strict API alignment
- No side effects
"""

import json
import time
import sys
import traceback
import requests

import splunklib.modularinput as smi


API_VERSION = "2024-10-01-preview"
RESOURCE_PROVIDER = "Microsoft.Security"
API_ROOT = "https://management.azure.com"


class DefenderEASMDomains(smi.Script):

    def get_scheme(self):
        scheme = smi.Scheme("Defender EASM Domains")
        scheme.description = "Collect domain assets from Microsoft Defender EASM"
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                name="name",
                description="Input name",
                required_on_create=True
            )
        )

        return scheme

    def validate_input(self, definition):
        # No runtime validation here
        return

    def stream_events(self, inputs, ew):
        for input_name, input_item in inputs.inputs.items():
            try:
                self._run_input(input_name, ew)
            except Exception as e:
                ew.log(
                    smi.EventWriter.ERROR,
                    f"defender_easm_domains failed: {e}\n{traceback.format_exc()}"
                )

    def _run_input(self, input_name, ew):
        session_key = self._input_definition.metadata["session_key"]

        config = self._load_app_config(session_key)

        tenant_id = config.get("tenant_id")
        subscription_id = config.get("subscription_id")
        resource_group = config.get("resource_group")
        workspace_name = config.get("workspace_name")
        client_id = config.get("client_id")
        authority_url = config.get(
            "authority_url",
            "https://login.microsoftonline.com"
        )

        access_token = self._get_access_token(
            tenant_id,
            client_id,
            authority_url,
            session_key
        )

        url = (
            f"{API_ROOT}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/{RESOURCE_PROVIDER}"
            f"/externalAttackSurfaceManagementWorkspaces/{workspace_name}"
            f"/assets/domains"
            f"?api-version={API_VERSION}"
        )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        while url:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()

            payload = resp.json()
            items = payload.get("value", [])

            for obj in items:
                ew.write_event(
                    smi.Event(
                        data=json.dumps(obj),
                        sourcetype="defender:easm:domain",
                        index=config.get("target_index", "security_defender_easm")
                    )
                )

            url = payload.get("nextLink")

    ############################################
    # AUTH / CONFIG
    ############################################

    def _load_app_config(self, session_key):
        import splunk.entity as entity

        app_conf = entity.getEntity(
            "configs/conf-app",
            "Microsoft_Defender_EASM_For_Splunk",
            namespace="Microsoft_Defender_EASM_For_Splunk",
            owner="nobody",
            sessionKey=session_key
        )

        return app_conf

    def _get_access_token(self, tenant_id, client_id, authority_url, session_key):
        import splunk.entity as entity

        secret = entity.getEntity(
            "storage/passwords",
            f"defender_easm:client_secret",
            namespace="Microsoft_Defender_EASM_For_Splunk",
            owner="nobody",
            sessionKey=session_key
        )

        client_secret = secret["clear_password"]

        token_url = f"{authority_url}/{tenant_id}/oauth2/v2.0/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://management.azure.com/.default"
        }

        resp = requests.post(token_url, data=data, timeout=30)
        resp.raise_for_status()

        return resp.json()["access_token"]


if __name__ == "__main__":
    smi.ScriptRunner(DefenderEASMDomains).run()
