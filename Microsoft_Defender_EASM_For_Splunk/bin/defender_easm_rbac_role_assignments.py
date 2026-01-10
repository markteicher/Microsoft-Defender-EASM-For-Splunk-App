#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: RBAC Role Assignments

Source:
- Microsoft Defender External Attack Surface Management (EASM)
- Control Plane API

Responsibilities:
- Retrieve RBAC role assignments
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

SOURCETYPE = "defender:easm:rbac:role_assignment"
API_PATH = "/roleAssignments"


class DefenderEASMRbacRoleAssignments(EASMModularInput):

    def collect(self):
        self.logger.info("Starting RBAC role assignments collection")

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
            params = None  # nextLink already includes parameters

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
            f"RBAC role assignments ingestion complete — "
            f"{total} records ingested"
        )


def main():
    try:
        DefenderEASMRbacRoleAssignments(
            asset_name="rbac_role_assignments",
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
