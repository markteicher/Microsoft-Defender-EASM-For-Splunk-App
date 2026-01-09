#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: Hosts

API:
GET /assets/hosts
(api-version=2024-10-01-preview)

Responsibilities:
- Authenticate via Azure AD (client credentials)
- Call Defender EASM Assets API
- Handle pagination via nextLink
- Emit raw JSON events to Splunk

Design constraints:
- NO enrichment
- NO transformation
- NO field invention
"""

import sys
import json
import time
import requests
from splunklib.modularinput import Script, Event, EventWriter
from azure.identity import ClientSecretCredential


API_VERSION = "2024-10-01-preview"
RESOURCE = "https://management.azure.com/.default"


class DefenderEASMHosts(Script):

    def get_scheme(self):
        scheme = self.Scheme("Defender EASM Hosts")
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = False
        scheme.use_single_instance = False
        return scheme

    def stream_events(self, inputs, ew: EventWriter):
        for input_name, input_item in inputs.inputs.items():
            self.collect_hosts(input_item, ew)

    def collect_hosts(self, input_item, ew):
        tenant_id = input_item["tenant_id"]
        client_id = input_item["client_id"]
        client_secret = input_item["client_secret"]
        subscription_id = input_item["subscription_id"]
        resource_group = input_item["resource_group"]
        workspace_name = input_item["workspace_name"]

        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )

        token = credential.get_token(RESOURCE).token

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Security"
            f"/externalAttackSurfaceManagementWorkspaces/{workspace_name}"
            f"/assets/hosts"
            f"?api-version={API_VERSION}"
        )

        while url:
            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            payload = response.json()

            for asset in payload.get("value", []):
                ew.write_event(Event(
                    data=json.dumps(asset),
                    sourcetype="defender:easm:host"
                ))

            url = payload.get("nextLink")
            time.sleep(0.2)


if __name__ == "__main__":
    sys.exit(DefenderEASMHosts().run(sys.argv))
