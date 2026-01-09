#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: WHOIS Contacts

Source:
- Microsoft Defender External Attack Surface Management (EASM) Data Plane API
- Asset Type: WhoisContact

Responsibilities:
- Authenticate using Azure AD credentials
- Retrieve WHOIS contact assets from EASM
- Handle pagination via nextLink
- Respect proxy configuration
- Write raw JSON events to Splunk
- Maintain checkpoint state

Design constraints:
- No enrichment
- No field mutation
- No CIM
- No dashboard assumptions
"""

import sys
import json
import time
from typing import Dict, Any

from defender_easm_common import (
    EASMModularInput,
    EASMCheckpoint,
    EASMAPIError,
)


ASSET_TYPE = "WhoisContact"
SOURCETYPE = "defender:easm:whois_contact"


class DefenderEASMWhoisContacts(EASMModularInput):
    """
    Modular input implementation for WHOIS Contact assets
    """

    def collect(self):
        """
        Main execution loop
        """

        self.logger.info("Starting WHOIS contact collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()

        self.logger.debug(f"Last checkpoint value: {last_checkpoint}")

        params = {
            "assetType": ASSET_TYPE,
            "$top": 100
        }

        if last_checkpoint:
            params["$filter"] = f"properties.lastSeenDateTime gt {last_checkpoint}"

        next_url = "/assets"

        event_count = 0
        newest_timestamp = last_checkpoint

        while next_url:
            response = self.api.get(next_url, params=params)

            assets = response.get("value", [])
            next_url = response.get("nextLink")
            params = None  # nextLink already contains params

            for asset in assets:
                self.write_event(
                    data=json.dumps(asset),
                    sourcetype=SOURCETYPE
                )
                event_count += 1

                observed = (
                    asset.get("properties", {})
                    .get("lastSeenDateTime")
                )

                if observed and (not newest_timestamp or observed > newest_timestamp):
                    newest_timestamp = observed

            self.logger.info(
                f"Fetched {len(assets)} WHOIS contacts "
                f"(total so far: {event_count})"
            )

        if newest_timestamp:
            checkpoint.set(newest_timestamp)
            self.logger.info(f"Checkpoint updated to {newest_timestamp}")

        self.logger.info(
            f"WHOIS contact collection complete — "
            f"{event_count} records ingested"
        )


def main():
    try:
        input_runner = DefenderEASMWhoisContacts(
            asset_name="whois_contacts",
            sourcetype=SOURCETYPE
        )
        input_runner.run()

    except EASMAPIError as exc:
        sys.stderr.write(f"EASM API error: {exc}\n")
        sys.exit(2)

    except Exception as exc:
        sys.stderr.write(f"Unhandled error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
