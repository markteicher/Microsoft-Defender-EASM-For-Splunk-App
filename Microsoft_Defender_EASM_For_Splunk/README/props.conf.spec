# props.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents supported props.conf settings for
# Microsoft Defender External Attack Surface Management data.
#
# All data is JSON-based and uses search-time field extraction.
# No index-time transforms or CIM normalization is performed.
#

############################################
# BASE SETTINGS (ALL EASM SOURCETYPES)
############################################

[defender:easm:*]

SHOULD_LINEMERGE = <boolean>
* Controls line merging behavior.
* Default: false

LINE_BREAKER = <regex>
* Regular expression defining event line breaks.

TRUNCATE = <integer>
* Maximum event size in bytes.
* 0 disables truncation.

KV_MODE = <string>
* Key-value extraction mode.
* Supported value: json

INDEXED_EXTRACTIONS = <string>
* Enables indexed JSON extraction.
* Supported value: json

NO_BINARY_CHECK = <boolean>
* Disables binary data checks.

CHARSET = <string>
* Character encoding.
* Default: UTF-8

TZ = <string>
* Time zone applied to extracted timestamps.
* Default: UTC

TIME_PREFIX = <regex>
* Regex used to locate timestamp fields in JSON payloads.

TIME_FORMAT = <string>
* Timestamp format.
* Example: %Y-%m-%dT%H:%M:%S.%3N

MAX_TIMESTAMP_LOOKAHEAD = <integer>
* Maximum characters to scan for timestamp.

############################################
# FIELD ALIASES (CANONICAL NORMALIZATION)
############################################

FIELDALIAS-easm_id = <field> AS <alias>
* Canonical EASM resource ID alias.

FIELDALIAS-easm_asset_type = <field> AS <alias>
* Asset type alias.

FIELDALIAS-easm_domain = <field> AS <alias>
* Domain name alias.

FIELDALIAS-easm_host = <field> AS <alias>
* Hostname alias.

FIELDALIAS-easm_ip_address = <field> AS <alias>
* IP address alias.

FIELDALIAS-easm_asn = <field> AS <alias>
* Autonomous System Number alias.

FIELDALIAS-easm_fingerprint = <field> AS <alias>
* SSL certificate fingerprint alias.

FIELDALIAS-easm_severity = <field> AS <alias>
* Severity level alias.

FIELDALIAS-easm_risk_level = <field> AS <alias>
* Risk level alias.

############################################
# ASSET INVENTORY SOURCETYPES
############################################

[defender:easm:domain]
FIELDALIAS-domain_name = <field> AS <alias>
FIELDALIAS-domain_id = <field> AS <alias>

[defender:easm:host]
FIELDALIAS-host_name = <field> AS <alias>
FIELDALIAS-host_id = <field> AS <alias>

[defender:easm:page]
FIELDALIAS-page_url = <field> AS <alias>

[defender:easm:ip_address]
FIELDALIAS-ip_value = <field> AS <alias>

[defender:easm:ip_block]
FIELDALIAS-ip_block_value = <field> AS <alias>

[defender:easm:asn]
FIELDALIAS-asn_number = <field> AS <alias>

[defender:easm:ssl_certificate]
FIELDALIAS-cert_thumbprint = <field> AS <alias>
FIELDALIAS-cert_subject = <field> AS <alias>

[defender:easm:whois_contact]
FIELDALIAS-contact_name = <field> AS <alias>
FIELDALIAS-contact_email = <field> AS <alias>

############################################
# DNS RECORDS
############################################

[defender:easm:dns_record]
FIELDALIAS-dns_record_name = <field> AS <alias>
FIELDALIAS-dns_record_type = <field> AS <alias>
FIELDALIAS-dns_record_value = <field> AS <alias>
FIELDALIAS-dns_record_ttl = <field> AS <alias>

############################################
# EXPOSURE INSIGHTS
############################################

[defender:easm:exposure_insight]
FIELDALIAS-insight_type = <field> AS <alias>
FIELDALIAS-insight_severity = <field> AS <alias>

############################################
# DISCOVERY & MANAGEMENT
############################################

[defender:easm:discovery_template]
FIELDALIAS-template_name = <field> AS <alias>
FIELDALIAS-template_state = <field> AS <alias>

[defender:easm:labels]
FIELDALIAS-label_name = <field> AS <alias>
FIELDALIAS-label_color = <field> AS <alias>

[defender:easm:billable_asset]
FIELDALIAS-billable_type = <field> AS <alias>

[defender:easm:data_connection]
FIELDALIAS-connection_type = <field> AS <alias>

############################################
# TASKS & OPERATIONS
############################################

[defender:easm:task]
FIELDALIAS-task_id = <field> AS <alias>
FIELDALIAS-task_status = <field> AS <alias>
FIELDALIAS-task_type = <field> AS <alias>

############################################
# PLATFORM HEALTH & LICENSE
############################################

[defender:easm:health]
FIELDALIAS-health_status = <field> AS <alias>

[defender:easm:license]
FIELDALIAS-license_expiration = <field> AS <alias>
