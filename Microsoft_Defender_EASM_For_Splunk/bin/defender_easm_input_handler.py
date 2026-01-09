#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input Management Handler

Responsibilities:
- List Defender EASM modular inputs
- Enable / disable inputs safely
- Report input status

Design constraints:
- NO ingestion logic
- NO API calls
- NO business logic
- Splunk REST handler only
"""

import json
import splunk.admin as admin
import splunk.entity as entity


APP_NAME = "Microsoft_Defender_EASM_For_Splunk"
INPUTS_CONF = "inputs"


class DefenderEASMInputHandler(admin.MConfigHandler):
    """
    Handles:
    - GET  /defender_easm/inputs
    - GET  /defender_easm/inputs/status
    - POST /defender_easm/inputs/enable
    - POST /defender_easm/inputs/disable
    """

    def setup(self):
        pass

    def handleList(self, confInfo):
        """
        List all Defender EASM modular inputs
        """
        inputs = entity.getEntities(
            [INPUTS_CONF],
            namespace=APP_NAME,
            owner="nobody"
        )

        for name, stanza in inputs.items():
            confInfo[name].append("disabled", stanza.get("disabled", "1"))
            confInfo[name].append("interval", stanza.get("interval"))
            confInfo[name].append("sourcetype", stanza.get("sourcetype"))
            confInfo[name].append("index", stanza.get("index"))

    def handleEdit(self, confInfo):
        """
        Enable or disable a modular input.
        Expects:
        - name
        - action = enable | disable
        """
        name = self.callerArgs.data.get("name")
        action = self.callerArgs.data.get("action")

        if not name or not action:
            raise admin.ArgValidationException(
                "Both 'name' and 'action' are required"
            )

        disabled_value = "0" if action == "enable" else "1"

        entity.setEntity(
            [INPUTS_CONF, name],
            {"disabled": disabled_value},
            namespace=APP_NAME,
            owner="nobody"
        )

        confInfo["result"].append("name", name)
        confInfo["result"].append("action", action)
        confInfo["result"].append("disabled", disabled_value)


if __name__ == "__main__":
    admin.init(DefenderEASMInputHandler, admin.CONTEXT_APP_AND_USER)
