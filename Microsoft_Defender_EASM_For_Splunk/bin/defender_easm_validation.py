#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Validation & Connectivity REST Handler

Responsibilities:
- Health endpoint
- Validation endpoint
- Test-connection endpoint

Design constraints:
- NO API calls
- NO token logic
- NO ingestion
- Deterministic responses only
"""

import splunk.admin as admin


class DefenderEASMValidationHandler(admin.MConfigHandler):

    ############################################
    # HEALTH / VALIDATION
    ############################################
    def handleList(self, confInfo):
        """
        GET /defender_easm/health
        GET /defender_easm/validate
        GET /defender_easm/test_connection
        """

        confInfo["status"].append("configured", "true")
        confInfo["status"].append(
            "message",
            "Defender EASM validation endpoint reachable"
        )

        confInfo["status"].append("result", "ok")

    ############################################
    # NO-OP EDIT (required for AppInspect safety)
    ############################################
    def handleEdit(self, confInfo):
        confInfo["result"].append("status", "ok")
        confInfo["result"].append(
            "message",
            "No editable parameters for validation endpoint"
        )


if __name__ == "__main__":
    admin.init(DefenderEASMValidationHandler, admin.CONTEXT_NONE)
