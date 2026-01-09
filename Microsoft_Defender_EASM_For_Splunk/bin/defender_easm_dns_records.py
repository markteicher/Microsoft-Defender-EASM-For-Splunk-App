#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: DNS Records

Source:
- Microsoft Defender External Attack Surface Management (EASM) Data Plane API
- Asset Type: DnsRecord

Responsibilities:
- Authenticate via Azure AD
- Retrieve DNS record assets (A, AAAA, MX, TXT, NS, CNAME, etc.)
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


ASSET_TYPE = "DnsRecord"
SOURCETYPE = "defender:easm:dns_record"


class DefenderEASMDnsRecords(EASMModularInput):
    """
    Modular input for DNS record assets
    """

    def collect(self):
        self.logger.info("Starting DNS record collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()

        self.logger.debug(f"Last checkpoint value: {last_checkpoint}")

        params = {
            "assetType": ASSET_TYPE,
            "$top": 200
        }

        if last_checkpoint:
            params["$filter"] = (
                f"properties.lastSeenDateTime gt {last_checkpoint}"
            )

        next_url = "/assets"
        event_count = 0
        newest_timestamp = last_checkpoint

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
                event_count += 1

                observed = (
                    record.get("properties", {})
                    .get("lastSeenDateTime")
                )

                if observed and (
                    not newest_timestamp or observed > newest_timestamp
                ):
                    newest_timestamp = observed

            self.logger.info(
                f"Fetched {len(records)} DNS records "
                f"(total so far: {event_count})"
            )

        if newest_timestamp:
            checkpoint.set(newest_timestamp)
            self.logger.info(f"Checkpoint updated to {newest_timestamp}")

        self.logger.info(
            f"DNS record collection complete — "
            f"{event_count} records ingested"
        )


def main():
    try:
        runner = DefenderEASMDnsRecords(
            asset_name="dns_records",
            sourcetype=SOURCETYPE
        )
        runner.run()

    except EASMAPIError as exc:
        sys.stderr.write(f"EASM API error: {exc}\n")
        sys.exit(2)

    except Exception as exc:
        sys.stderr.write(f"Unhandled error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
