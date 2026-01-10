# savedsearches.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents supported saved searches shipped with the app.
# All searches are disabled by default and intended for use by
# dashboards, ad-hoc execution, or optional scheduling by administrators.
#

############################################
# OVERVIEW — ASSET COUNTS
############################################

[EASM - Count Domains]
search = <search string>
* Counts domain assets ingested from Defender EASM.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count Hosts]
search = <search string>
* Counts host assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count Pages]
search = <search string>
* Counts page assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count SSL Certificates]
search = <search string>
* Counts SSL certificate assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count ASNs]
search = <search string>
* Counts ASN assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count IP Blocks]
search = <search string>
* Counts IP block assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count IP Addresses]
search = <search string>
* Counts IP address assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Count WHOIS Contacts]
search = <search string>
* Counts WHOIS contact assets.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

############################################
# OVERVIEW — ATTACK SURFACE INSIGHTS
############################################

[EASM - High Priority Findings]
search = <search string>
* Counts high severity exposure insight records.

dispatch.earliest_time = <time>
* Default: -30d@d

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Medium Priority Findings]
search = <search string>
* Counts medium severity exposure insight records.

dispatch.earliest_time = <time>
* Default: -30d@d

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

[EASM - Low Priority Findings]
search = <search string>
* Counts low severity exposure insight records.

dispatch.earliest_time = <time>
* Default: -30d@d

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

############################################
# INVENTORY — ASSET DISTRIBUTION
############################################

[EASM - Asset Inventory Breakdown]
search = <search string>
* Provides a breakdown of assets by sourcetype.

dispatch.earliest_time = <time>
* Default: -30d@d

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

############################################
# TASKING — TASK STATUS
############################################

[EASM - Tasks by Status]
search = <search string>
* Summarizes task records by task status.

dispatch.earliest_time = <time>
* Default: -30d@d

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

############################################
# TRENDS
############################################

[EASM - Asset Growth Over Time]
search = <search string>
* Shows asset growth trends over time.

dispatch.earliest_time = <time>
* Default: -30d@d

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0

############################################
# HEALTH / INGESTION
############################################

[EASM - Ingestion Volume by Sourcetype]
search = <search string>
* Displays ingestion volume grouped by sourcetype.

dispatch.earliest_time = <time>
* Default: -24h

dispatch.latest_time = <time>
* Default: now

enableSched = <boolean>
* Default: 0
