#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: Data Connection Validation

Source:
- Microsoft Defender External Attack Surface Management (EASM)
- Control Plane API

Responsibilities:
- Retrieve validation status for configured data connections
- Handle pagination (nextLink)
- Respect proxy configuration
- Write raw JSON validation events to Splunk
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

SOURCETYPE = "defender:easm:data_connection_validation"
API_PATH = "/dataConnections/validationResults"


class DefenderEASMDataConnectionValidation(EASMModularInput):

    def collect(self):
        self.logger.info("Starting data connection validation collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()

        params = {"$top": 200}
        if last_checkpoint:
            params["$filter"] = (
                f"properties.lastCheckedDateTime gt {last_checkpoint}"
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
                    .get("lastCheckedDateTime")
                )

                if ts and (not newest_timestamp or ts > newest_timestamp):
                    newest_timestamp = ts

        if newest_timestamp:
            checkpoint.set(newest_timestamp)
            self.logger.info(f"Checkpoint updated to {newest_timestamp}")

        self.logger.info(
            f"Data connection validation ingestion complete — {total} records"
        )


def main():
    try:
        DefenderEASMDataConnectionValidation(
            asset_name="data_connection_validation",
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
