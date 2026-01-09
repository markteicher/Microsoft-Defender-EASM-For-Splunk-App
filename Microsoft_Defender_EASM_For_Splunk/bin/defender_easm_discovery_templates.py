#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: Discovery Templates
"""

import sys
import json

from defender_easm_common import (
    EASMModularInput,
    EASMCheckpoint,
    EASMAPIError,
)

SOURCETYPE = "defender:easm:discovery_template"
API_PATH = "/discoveryTemplates"


class DefenderEASMDiscoveryTemplates(EASMModularInput):

    def collect(self):
        self.logger.info("Starting discovery template collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()

        params = {"$top": 200}
        if last_checkpoint:
            params["$filter"] = f"properties.lastUpdatedDateTime gt {last_checkpoint}"

        next_url = API_PATH
        newest_timestamp = last_checkpoint
        total = 0

        while next_url:
            response = self.api.get(next_url, params=params)
            records = response.get("value", [])
            next_url = response.get("nextLink")
            params = None

            for record in records:
                self.write_event(json.dumps(record), sourcetype=SOURCETYPE)
                total += 1

                ts = record.get("properties", {}).get("lastUpdatedDateTime")
                if ts and (not newest_timestamp or ts > newest_timestamp):
                    newest_timestamp = ts

        if newest_timestamp:
            checkpoint.set(newest_timestamp)

        self.logger.info(f"Discovery template ingestion complete — {total} records")


def main():
    try:
        DefenderEASMDiscoveryTemplates(
            asset_name="discovery_templates",
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
