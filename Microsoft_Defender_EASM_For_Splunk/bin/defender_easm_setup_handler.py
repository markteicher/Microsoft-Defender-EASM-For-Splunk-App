# bin/defender_easm_setup_handler.py
#
# Microsoft Defender EASM for Splunk App
# Setup & Configuration REST Handler

import json
import splunk.admin as admin
import splunk.entity as entity

APP_NAME = "Microsoft_Defender_EASM_For_Splunk"

class DefenderEASMSetupHandler(admin.MConfigHandler):

    def setup(self):
        if self.requestedAction in (admin.ACTION_CREATE, admin.ACTION_EDIT):
            for arg in [
                "tenant_id",
                "subscription_id",
                "resource_group",
                "workspace_name",
                "client_id",
                "client_secret",
                "authority_url",
                "target_index",
                "use_proxy",
                "proxy_url",
                "proxy_username",
                "proxy_password",
            ]:
                self.supportedArgs.addOptArg(arg)

    def handleCreate(self, confInfo):
        self._save_config()

    def handleEdit(self, confInfo):
        self._save_config()

    def handleList(self, confInfo):
        conf = entity.getEntity(
            "configs/conf-app",
            APP_NAME,
            namespace=APP_NAME,
            owner="nobody"
        )

        for k, v in conf.items():
            confInfo["setup"][k] = v

    def _save_config(self):
        sessionKey = self.getSessionKey()

        # Save non-secrets
        app_conf = entity.getEntity(
            "configs/conf-app",
            APP_NAME,
            namespace=APP_NAME,
            owner="nobody"
        )

        for key in self.callerArgs:
            if key not in ("client_secret", "proxy_password"):
                app_conf[key] = self.callerArgs[key][0]

        entity.setEntity(app_conf, sessionKey)

        # Save secrets securely
        for secret in ("client_secret", "proxy_password"):
            if secret in self.callerArgs:
                entity.setEntity(
                    entity.getEntity(
                        "storage/passwords",
                        f"defender_easm:{secret}",
                        namespace=APP_NAME,
                        owner="nobody",
                        sessionKey=sessionKey,
                        create=True
                    ),
                    sessionKey
                )


if __name__ == "__main__":
    admin.init(DefenderEASMSetupHandler, admin.CONTEXT_NONE)
