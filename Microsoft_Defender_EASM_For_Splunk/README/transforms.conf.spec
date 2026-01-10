# transforms.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents search-time field extraction transforms
# shipped with the application. These transforms are designed
# to normalize commonly used Defender EASM fields when they
# appear in nested or unflattened JSON payloads.
#
# All transforms are optional and applied only if referenced
# by props.conf or invoked explicitly.
#

########################################
# CANONICAL EASM RESOURCE ID
########################################

[easm_id]
REGEX = <regular expression>
* Extracts the full Defender EASM resource ID from JSON payloads.

FORMAT = <field format>
* Writes extracted value to field: easm_id

########################################
# ASSET TYPE
########################################

[easm_asset_type]
REGEX = <regular expression>
* Extracts assetType when present in unflattened payloads.

FORMAT = <field format>
* Writes extracted value to field: asset_type

########################################
# DOMAIN NAME
########################################

[easm_domain]
REGEX = <regular expression>
* Extracts domain name from nested payload structures.

FORMAT = <field format>
* Writes extracted value to field: domain

########################################
# HOST NAME
########################################

[easm_host]
REGEX = <regular expression>
* Extracts hostName values from discovery and task payloads.

FORMAT = <field format>
* Writes extracted value to field: host

########################################
# IP ADDRESS
########################################

[easm_ip_address]
REGEX = <regular expression>
* Extracts IP address values from exposure or findings payloads.

FORMAT = <field format>
* Writes extracted value to field: ip_address

########################################
# ASN
########################################

[easm_asn]
REGEX = <regular expression>
* Extracts Autonomous System Number values.

FORMAT = <field format>
* Writes extracted value to field: asn

########################################
# SSL CERTIFICATE FINGERPRINT
########################################

[easm_cert_fingerprint]
REGEX = <regular expression>
* Extracts SSL certificate fingerprint values.

FORMAT = <field format>
* Writes extracted value to field: ssl_fingerprint

########################################
# WHOIS EMAIL
########################################

[easm_whois_email]
REGEX = <regular expression>
* Extracts WHOIS contact email addresses.

FORMAT = <field format>
* Writes extracted value to field: whois_email

########################################
# SEVERITY
########################################

[easm_severity]
REGEX = <regular expression>
* Extracts severity values when present.

FORMAT = <field format>
* Writes extracted value to field: severity

########################################
# RISK LEVEL
########################################

[easm_risk_level]
REGEX = <regular expression>
* Extracts riskLevel values when present.

FORMAT = <field format>
* Writes extracted value to field: risk_level
