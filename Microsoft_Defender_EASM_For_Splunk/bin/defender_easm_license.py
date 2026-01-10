#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: License

Source:
- Microsoft Defender External Attack Surface Management (EASM)
- Control Plane API

Responsibilities:
- Retrieve EASM license / entitlement information
- Respect proxy configuration
- Write raw JSON events to Splunk
- Maintain checkpoint state (defensive; license rarely changes)

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

SOURCETYPE = "defender:easm:license"
API_PATH = "/license"


class DefenderEASMLicense(EASMModularInput):

    def collect(self):
        self.logger.info("Starting EASM license collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()

        response = self.api.get(API_PATH)
        newest_timestamp = last_checkpoint
        total = 0

        # License endpoint may return a single object or wrapped value
        records = []
        if isinstance(response, dict):
            if "value" in response and isinstance(response["value"], list):
                records = response["value"]
            else:
                records = [response]

        for record in records:
            self.write_event(
                data=json.dumps(record),
                sourcetype=SOURCETYPE
            )
            total += 1

            ts = (
                record.get("properties", {})
                .get("lastUpdatedDateTime")
                or record.get("lastUpdatedDateTime")
            )

            if ts and (not newest_timestamp or ts > newest_timestamp):
                newest_timestamp = ts

        if newest_timestamp:
            checkpoint.set(newest_timestamp)
            self.logger.info(f"Checkpoint updated to {newest_timestamp}")

        self.logger.info(
            f"EASM license ingestion complete — "
            f"{total} records ingested"
        )


def main():
    try:
        DefenderEASMLicense(
            asset_name="license",
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
