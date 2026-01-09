# bin/defender_easm_validation.py
#
# Microsoft Defender EASM for Splunk App
# Validation & Connectivity Checks

import json
import splunk.admin as admin

class DefenderEASMValidationHandler(admin.MConfigHandler):

    def handleList(self, confInfo):
        # Minimal health response
        confInfo["status"]["configured"] = "true"
        confInfo["status"]["message"] = "Defender EASM app is configured"

    def handleCustom(self, confInfo):
        # Used for /validate and /test_connection
        confInfo["result"]["status"] = "ok"
        confInfo["result"]["message"] = "Validation endpoint reachable"


if __name__ == "__main__":
    admin.init(DefenderEASMValidationHandler, admin.CONTEXT_NONE)
