# inputs.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file defines the supported modular inputs for the
# Microsoft Defender External Attack Surface Management (EASM)
# Splunk App.
#
# These inputs retrieve data from the Microsoft Defender EASM
# Data Plane APIs and write raw JSON events into Splunk.
#
# All inputs are disabled by default.
#

############################
# COMMON KEYS (ALL INPUTS)
############################

[<stanza>]
disabled = <boolean>
* Indicates whether the modular input is disabled.
* Default: true

interval = <integer>
* Execution interval in seconds.

sourcetype = <string>
* Sourcetype assigned to events produced by this input.

index = <string>
* Target index for ingested events.

############################
# CORE INVENTORY (DATA PLANE)
############################

[defender_easm_domains]
* Collects domain assets from Defender EASM.

[defender_easm_hosts]
* Collects host assets from Defender EASM.

[defender_easm_pages]
* Collects discovered web page assets from Defender EASM.

[defender_easm_ip_addresses]
* Collects individual IP address assets from Defender EASM.

[defender_easm_ip_blocks]
* Collects IP block assets from Defender EASM.

[defender_easm_asns]
* Collects Autonomous System Number (ASN) assets from Defender EASM.

[defender_easm_ssl_certificates]
* Collects SSL/TLS certificate assets from Defender EASM.

[defender_easm_whois_contacts]
* Collects WHOIS contact records from Defender EASM.

[defender_easm_dns_records]
* Collects DNS record assets (A, AAAA, CNAME, MX, TXT, NS, etc.)
* from Defender EASM.

############################
# EXPOSURE / ATTACK SURFACE
############################

[defender_easm_exposure_insights]
* Collects exposure insight records.
* Used to derive OWASP, CWE, CISA KEV, and GDPR dashboards.

############################
# DISCOVERY & TASKING
############################

[defender_easm_discovery_templates]
* Collects discovery template definitions.

[defender_easm_discovery_runs]
* Collects discovery execution runs.

[defender_easm_tasks]
* Collects task execution records.

############################
# DATA CONNECTIONS
############################

[defender_easm_data_connections]
* Collects configured data connection resources.

[defender_easm_data_connection_validation]
* Collects data connection validation results.

############################
# REPORTING
############################

[defender_easm_reports]
* Collects report definitions.

[defender_easm_report_output]
* Collects generated report output artifacts.

############################
# RBAC & CONTROL PLANE
############################

[defender_easm_rbac_role_definitions]
* Collects RBAC role definition objects.

[defender_easm_rbac_role_assignments]
* Collects RBAC role assignment objects.

[defender_easm_workspaces]
* Collects Defender EASM workspace metadata.

[defender_easm_operations]
* Collects long-running operation records.

[defender_easm_license]
* Collects Defender EASM license information.
