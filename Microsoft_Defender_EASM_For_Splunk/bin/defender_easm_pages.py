#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: Pages

Collects page assets from Microsoft Defender External Attack Surface Management.
"""

import json
import traceback
import requests

import splunklib.modularinput as smi


API_VERSION = "2024-10-01-preview"
RESOURCE_PROVIDER = "Microsoft.Security"
API_ROOT = "https://management.azure.com"


class DefenderEASMPages(smi.Script):

    def get_scheme(self):
        scheme = smi.Scheme("Defender EASM Pages")
        scheme.description = "Collect page assets from Microsoft Defender EASM"
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
        return

    def stream_events(self, inputs, ew):
        for _ in inputs.inputs:
            try:
                self._run_input(ew)
            except Exception as e:
                ew.log(
                    smi.EventWriter.ERROR,
                    f"defender_easm_pages failed: {e}\n{traceback.format_exc()}"
                )

    def _run_input(self, ew):
        session_key = self._input_definition.metadata["session_key"]
        config = self._load_app_config(session_key)
        access_token = self._get_access_token(session_key, config)

        url = (
            f"{API_ROOT}/subscriptions/{config['subscription_id']}"
            f"/resourceGroups/{config['resource_group']}"
            f"/providers/{RESOURCE_PROVIDER}"
            f"/externalAttackSurfaceManagementWorkspaces/{config['workspace_name']}"
            f"/assets/pages"
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

            for item in payload.get("value", []):
                ew.write_event(
                    smi.Event(
                        data=json.dumps(item),
                        sourcetype="defender:easm:page",
                        index=config.get("target_index", "security_defender_easm")
                    )
                )

            url = payload.get("nextLink")

    ############################################
    # CONFIG & AUTH
    ############################################

    def _load_app_config(self, session_key):
        import splunk.entity as entity

        return entity.getEntity(
            "configs/conf-app",
            "Microsoft_Defender_EASM_For_Splunk",
            namespace="Microsoft_Defender_EASM_For_Splunk",
            owner="nobody",
            sessionKey=session_key
        )

    def _get_access_token(self, session_key, config):
        import splunk.entity as entity

        secret = entity.getEntity(
            "storage/passwords",
            "defender_easm:client_secret",
            namespace="Microsoft_Defender_EASM_For_Splunk",
            owner="nobody",
            sessionKey=session_key
        )

        token_url = f"{config['authority_url']}/{config['tenant_id']}/oauth2/v2.0/token"

        resp = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": config["client_id"],
                "client_secret": secret["clear_password"],
                "scope": "https://management.azure.com/.default",
            },
            timeout=30
        )

        resp.raise_for_status()
        return resp.json()["access_token"]


if __name__ == "__main__":
    smi.ScriptRunner(DefenderEASMPages).run()
