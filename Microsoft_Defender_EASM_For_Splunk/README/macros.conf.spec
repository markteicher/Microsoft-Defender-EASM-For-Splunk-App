# macros.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents supported macros for use in dashboards,
# saved searches, and ad-hoc queries.
#
# Macros are field-safe abstractions only and do not perform
# evaluation, enrichment, or compliance logic.
#

############################################
# CORE INDEX MACROS
############################################

[easm_index]
definition = <search string>
* Defines the index containing Defender EASM data.
* Default: index=security_defender_easm

iseval = <boolean>
* Indicates whether the macro is evaluated.
* Default: 0

############################################
# CORE SOURCETYPE MACROS
############################################

[easm_sourcetypes]
definition = <search string>
* Expands to all Defender EASM sourcetypes.
* Default: sourcetype=defender:easm:*

iseval = <boolean>
* Default: 0

[easm_assets_sourcetypes]
definition = <search string>
* Filters to EASM asset inventory sourcetypes:
  - domain
  - host
  - page
  - ip_address
  - ip_block
  - asn
  - ssl_certificate
  - whois_contact
  - dns_record

iseval = <boolean>
* Default: 0

############################################
# ASSET TYPE FILTER MACROS
############################################

[easm_domains]
definition = <search string>
* Filters to domain assets.

iseval = <boolean>
* Default: 0

[easm_hosts]
definition = <search string>
* Filters to host assets.

iseval = <boolean>
* Default: 0

[easm_pages]
definition = <search string>
* Filters to page assets.

iseval = <boolean>
* Default: 0

[easm_ip_addresses]
definition = <search string>
* Filters to IP address assets.

iseval = <boolean>
* Default: 0

[easm_ip_blocks]
definition = <search string>
* Filters to IP block assets.

iseval = <boolean>
* Default: 0

[easm_asns]
definition = <search string>
* Filters to ASN assets.

iseval = <boolean>
* Default: 0

[easm_ssl_certificates]
definition = <search string>
* Filters to SSL certificate assets.

iseval = <boolean>
* Default: 0

[easm_whois_contacts]
definition = <search string>
* Filters to WHOIS contact assets.

iseval = <boolean>
* Default: 0

[easm_dns_records]
definition = <search string>
* Filters to DNS record assets.

iseval = <boolean>
* Default: 0

############################################
# EXPOSURE / ATTACK SURFACE
############################################

[easm_exposure_insights]
definition = <search string>
* Filters to exposure insight records.

iseval = <boolean>
* Default: 0

############################################
# DISCOVERY & TASKING
############################################

[easm_tasks]
definition = <search string>
* Filters to task records.

iseval = <boolean>
* Default: 0

[easm_discovery_templates]
definition = <search string>
* Filters to discovery template records.

iseval = <boolean>
* Default: 0

[easm_discovery_runs]
definition = <search string>
* Filters to discovery run records.

iseval = <boolean>
* Default: 0

############################################
# DATA CONNECTIONS
############################################

[easm_data_connections]
definition = <search string>
* Filters to data connection records.

iseval = <boolean>
* Default: 0

[easm_data_connection_validation]
definition = <search string>
* Filters to data connection validation records.

iseval = <boolean>
* Default: 0

############################################
# REPORTING
############################################

[easm_reports]
definition = <search string>
* Filters to report metadata records.

iseval = <boolean>
* Default: 0

[easm_report_output]
definition = <search string>
* Filters to report output records.

iseval = <boolean>
* Default: 0

############################################
# RBAC / CONTROL PLANE
############################################

[easm_rbac_role_definitions]
definition = <search string>
* Filters to RBAC role definition records.

iseval = <boolean>
* Default: 0

[easm_rbac_role_assignments]
definition = <search string>
* Filters to RBAC role assignment records.

iseval = <boolean>
* Default: 0

[easm_workspaces]
definition = <search string>
* Filters to workspace records.

iseval = <boolean>
* Default: 0

[easm_operations]
definition = <search string>
* Filters to operational records.

iseval = <boolean>
* Default: 0

[easm_license]
definition = <search string>
* Filters to license records.

iseval = <boolean>
* Default: 0

############################################
# TIME RANGE SAFETY MACROS
############################################

[easm_last_24h]
definition = <search string>
* Restricts search to the last 24 hours.

iseval = <boolean>
* Default: 0

[easm_last_7d]
definition = <search string>
* Restricts search to the last 7 days.

iseval = <boolean>
* Default: 0

[easm_last_30d]
definition = <search string>
* Restricts search to the last 30 days.

iseval = <boolean>
* Default: 0
