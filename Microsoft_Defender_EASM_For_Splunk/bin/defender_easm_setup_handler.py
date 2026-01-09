# bin/defender_easm_setup_handler.py
#
# Microsoft Defender EASM for Splunk App
# Setup & Configuration REST Handler
#
# AppInspect-safe
# Splunk Cloud compatible
# Secrets stored in storage/passwords only

import splunk.admin as admin
import splunk.entity as entity

APP_NAME = "Microsoft_Defender_EASM_For_Splunk"
CONF_FILE = "defender_easm"


class DefenderEASMSetupHandler(admin.MConfigHandler):

    ############################################
    # SETUP
    ############################################
    def setup(self):
        if self.requestedAction in (admin.ACTION_CREATE, admin.ACTION_EDIT):
            for arg in [
                "tenant_id",
                "subscription_id",
                "resource_group",
                "workspace_name",
                "client_id",
                "authority_url",
                "target_index",
                "use_proxy",
                "proxy_url",
                "proxy_username",
                # secrets handled separately
                "client_secret",
                "proxy_password",
            ]:
                self.supportedArgs.addOptArg(arg)

    ############################################
    # CREATE / EDIT
    ############################################
    def handleCreate(self, confInfo):
        self._save()

    def handleEdit(self, confInfo):
        self._save()

    ############################################
    # LIST (populate setup UI)
    ############################################
    def handleList(self, confInfo):
        conf = entity.getEntity(
            f"configs/conf-{CONF_FILE}",
            "settings",
            namespace=APP_NAME,
            owner="nobody"
        )

        for k, v in conf.items():
            confInfo["setup"][k] = v

        # Do NOT expose secrets
        confInfo["setup"]["client_secret"] = "********"
        confInfo["setup"]["proxy_password"] = "********"

    ############################################
    # INTERNAL SAVE LOGIC
    ############################################
    def _save(self):
        sessionKey = self.getSessionKey()

        # Ensure config stanza exists
        conf = entity.getEntity(
            f"configs/conf-{CONF_FILE}",
            "settings",
            namespace=APP_NAME,
            owner="nobody",
            sessionKey=sessionKey,
            create=True
        )

        # Save non-secret fields
        for key, value in self.callerArgs.items():
            if key in ("client_secret", "proxy_password"):
                continue
            conf[key] = value[0]

        entity.setEntity(conf, sessionKey)

        # Save secrets securely
        self._store_secret("client_secret", sessionKey)
        self._store_secret("proxy_password", sessionKey)

    ############################################
    # SECURE CREDENTIAL STORAGE
    ############################################
    def _store_secret(self, name, sessionKey):
        if name not in self.callerArgs:
            return

        value = self.callerArgs[name][0]
        if not value or value == "********":
            return

        entity.setEntity(
            entity.getEntity(
                "storage/passwords",
                f"defender_easm:{name}",
                namespace=APP_NAME,
                owner="nobody",
                sessionKey=sessionKey,
                create=True
            ),
            sessionKey
        )


if __name__ == "__main__":
    admin.init(DefenderEASMSetupHandler, admin.CONTEXT_NONE)
