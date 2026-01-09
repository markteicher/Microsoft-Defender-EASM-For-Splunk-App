#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Microsoft Defender EASM for Splunk App
Modular Input: Exposure Insights

Source:
- Microsoft Defender External Attack Surface Management (EASM) Data Plane API
- Resource: Exposure Insights

Responsibilities:
- Authenticate via Azure AD (handled in defender_easm_common)
- Retrieve exposure insights (raw JSON)
- Handle pagination (nextLink)
- Respect proxy configuration
- Write raw JSON events to Splunk
- Maintain checkpoint state (incremental collection)

Design constraints:
- No enrichment
- No field mutation
- No CIM alignment
- Raw JSON only
"""

import sys
import json
from typing import Optional

from defender_easm_common import (
    EASMModularInput,
    EASMCheckpoint,
    EASMAPIError,
)

SOURCETYPE = "defender:easm:exposure_insight"

# Data-plane path (common module should prepend the workspace base URL)
ENDPOINT = "/exposureInsights"

# OData page size
PAGE_SIZE = 200

# Prefer "lastUpdatedDateTime" when present; fall back safely.
TS_CANDIDATES = (
    ("properties", "lastUpdatedDateTime"),
    ("properties", "lastSeenDateTime"),
    ("properties", "observedDateTime"),
    ("properties", "createdDateTime"),
    ("properties", "createdDate"),
    ("properties", "timestamp"),
    ("lastUpdatedDateTime",),
    ("observedDateTime",),
    ("createdDateTime",),
    ("timestamp",),
)


def _get_nested(obj, path):
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
        if cur is None:
            return None
    return cur


def _pick_timestamp(record) -> Optional[str]:
    """
    Return the best available ISO-ish timestamp string from an insight record.
    We keep it as a string so we can use lexicographic compare for ISO 8601.
    """
    for p in TS_CANDIDATES:
        v = _get_nested(record, p)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _odata_datetimeoffset(ts: str) -> str:
    """
    Wrap an ISO timestamp for OData datetimeoffset comparisons.

    Example:
      datetimeoffset'2024-10-20T15:04:05Z'
    """
    # Keep it minimal and strict: no parsing, no mutation.
    return f"datetimeoffset'{ts}'"


class DefenderEASMExposureInsights(EASMModularInput):
    """
    Modular input for Exposure Insights
    """

    def collect(self):
        self.logger.info("Starting Exposure Insights collection")

        checkpoint = EASMCheckpoint(self)
        last_checkpoint = checkpoint.get()
        self.logger.debug(f"Last checkpoint value: {last_checkpoint}")

        params = {"$top": PAGE_SIZE}

        # Use a conservative incremental filter if we have a checkpoint.
        # We prefer properties/lastUpdatedDateTime (common in EASM payloads).
        if last_checkpoint:
            params["$filter"] = (
                f"properties/lastUpdatedDateTime gt {_odata_datetimeoffset(last_checkpoint)}"
            )

        next_url = ENDPOINT
        event_count = 0
        newest_timestamp = last_checkpoint

        while next_url:
            response = self.api.get(next_url, params=params)

            # After first request, nextLink is expected to be fully-formed.
            # Many APIs include query params in nextLink, so we must stop passing params.
            records = response.get("value") or []
            next_url = response.get("nextLink")
            params = None

            for rec in records:
                self.write_event(data=json.dumps(rec), sourcetype=SOURCETYPE)
                event_count += 1

                observed = _pick_timestamp(rec)
                if observed and (not newest_timestamp or observed > newest_timestamp):
                    newest_timestamp = observed

            self.logger.info(
                f"Fetched {len(records)} exposure insights (total so far: {event_count})"
            )

        if newest_timestamp and newest_timestamp != last_checkpoint:
            checkpoint.set(newest_timestamp)
            self.logger.info(f"Checkpoint updated to {newest_timestamp}")

        self.logger.info(
            f"Exposure Insights collection complete — {event_count} records ingested"
        )


def main():
    try:
        runner = DefenderEASMExposureInsights(
            asset_name="exposure_insights",
            sourcetype=SOURCETYPE,
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
