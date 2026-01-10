#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: RBAC Role Definitions

Source:
- Microsoft Defender External Attack Surface Management (EASM)
- Control Plane API

Responsibilities:
- Retrieve RBAC role definitions
- Handle pagination (nextLink)
- Respect proxy configuration
- Write raw JSON events to Splunk
- Maintain checkpoint state

Design constraints:
- No enrichment
- No field mutation
- No CIM alignment
- Raw JSON only
"""

import sys
import json

from defender_easm_common import (
    EASMModularInput,
    EASMCheckpoint,
    EASMAPIError,
)

SOURCETYPE = "defender:easm:rbac:role_definition"
API_PATH = "/roleDefinitions"


class DefenderEASMRbacRoleDefinitions(EASMModularInput):

    def collect(self):
        self.logger.info("Starting RBAC role definitions collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()

        params = {"$top": 200}
        if last_checkpoint:
            params["$filter"] = (
                f"properties.lastUpdatedDateTime gt {last_checkpoint}"
            )

        next_url = API_PATH
        newest_timestamp = last_checkpoint
        total = 0

        while next_url:
            response = self.api.get(next_url, params=params)
            records = response.get("value", [])
            next_url = response.get("nextLink")
            params = None  # nextLink already contains params

            for record in records:
                self.write_event(
                    data=json.dumps(record),
                    sourcetype=SOURCETYPE
                )
                total += 1

                ts = (
                    record.get("properties", {})
                    .get("lastUpdatedDateTime")
                )

                if ts and (not newest_timestamp or ts > newest_timestamp):
                    newest_timestamp = ts

        if newest_timestamp:
            checkpoint.set(newest_timestamp)
            self.logger.info(f"Checkpoint updated to {newest_timestamp}")

        self.logger.info(
            f"RBAC role definitions ingestion complete — "
            f"{total} records ingested"
        )


def main():
    try:
        DefenderEASMRbacRoleDefinitions(
            asset_name="rbac_role_definitions",
            sourcetype=SOURCETYPE
        ).run()

    except EASMAPIError as exc:
        sys.stderr.write(f"EASM API error: {exc}\n")
        sys.exit(2)

    except Exception as exc:
        sys.stderr.write(f"Unhandled error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
