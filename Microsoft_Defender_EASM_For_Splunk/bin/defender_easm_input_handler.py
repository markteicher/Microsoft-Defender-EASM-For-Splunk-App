#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input Management REST Handler

Responsibilities:
- List modular inputs
- Report status
- Enable / disable inputs

NO ingestion logic
NO API calls
NO business logic
"""

import splunk.admin as admin
import splunk.entity as entity

APP_NAME = "Microsoft_Defender_EASM_For_Splunk"
CONF_FILE = "inputs"


class DefenderEASMInputHandler(admin.MConfigHandler):

    ############################################
    # SETUP
    ############################################
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            self.supportedArgs.addReqArg("name")
            self.supportedArgs.addReqArg("action")

    ############################################
    # LIST INPUTS
    ############################################
    def handleList(self, confInfo):
        """
        GET /defender_easm/inputs
        """
        inputs = entity.getEntities(
            f"configs/conf-{CONF_FILE}",
            namespace=APP_NAME,
            owner="nobody"
        )

        for name, stanza in inputs.items():
            confInfo[name].append("disabled", stanza.get("disabled", "1"))
            confInfo[name].append("interval", stanza.get("interval"))
            confInfo[name].append("sourcetype", stanza.get("sourcetype"))
            confInfo[name].append("index", stanza.get("index"))

    ############################################
    # ENABLE / DISABLE INPUT
    ############################################
    def handleEdit(self, confInfo):
        """
        POST /defender_easm/inputs/enable
        POST /defender_easm/inputs/disable
        """
        name = self.callerArgs["name"][0]
        action = self.callerArgs["action"][0]

        if action not in ("enable", "disable"):
            raise admin.ArgValidationException(
                "action must be 'enable' or 'disable'"
            )

        disabled_value = "0" if action == "enable" else "1"

        stanza = entity.getEntity(
            f"configs/conf-{CONF_FILE}",
            name,
            namespace=APP_NAME,
            owner="nobody"
        )

        stanza["disabled"] = disabled_value
        entity.setEntity(stanza, self.getSessionKey())

        confInfo["result"].append("name", name)
        confInfo["result"].append("action", action)
        confInfo["result"].append("disabled", disabled_value)


if __name__ == "__main__":
    admin.init(DefenderEASMInputHandler, admin.CONTEXT_NONE)
