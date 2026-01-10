# web.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents supported settings for controlling
# Splunk Web exposure of the Microsoft Defender EASM app.
#
# The app exposes setup, validation, health, and modular
# input management endpoints via REST handlers defined
# in restmap.conf.
#

############################################
# APPLICATION WEB SETTINGS
############################################

[settings]
enableSplunkWebSSL = <boolean>
* Controls whether Splunk Web SSL is enabled for this app.
* Default: false

############################################
# APP SETUP EXPOSURE
############################################

[expose:setup]
methods = <comma-separated list>
* HTTP methods allowed for the setup endpoint.

pattern = <string>
* URL pattern exposed under Splunk Web.

############################################
# REST ENDPOINT EXPOSURE — SETUP & VALIDATION
############################################

[expose:defender_easm_setup]
methods = <comma-separated list>
* Allowed HTTP methods for the Defender EASM setup endpoint.

pattern = <string>
* REST path mapped to the setup handler.

[expose:defender_easm_setup_reload]
methods = <comma-separated list>
* Allowed HTTP methods for setup reload operations.

pattern = <string>
* REST path for triggering configuration reload.

[expose:defender_easm_validate]
methods = <comma-separated list>
* Allowed HTTP methods for validation checks.

pattern = <string>
* REST path for validation endpoint.

[expose:defender_easm_test_connection]
methods = <comma-separated list>
* Allowed HTTP methods for connectivity testing.

pattern = <string>
* REST path for test connection endpoint.

############################################
# MODULAR INPUT MANAGEMENT
############################################

[expose:defender_easm_inputs]
methods = <comma-separated list>
* Allowed HTTP methods for listing modular inputs.

pattern = <string>
* REST path for modular input listing.

[expose:defender_easm_inputs_status]
methods = <comma-separated list>
* Allowed HTTP methods for retrieving modular input status.

pattern = <string>
* REST path for modular input status.

[expose:defender_easm_inputs_enable]
methods = <comma-separated list>
* Allowed HTTP methods for enabling modular inputs.

pattern = <string>
* REST path for enabling inputs.

[expose:defender_easm_inputs_disable]
methods = <comma-separated list>
* Allowed HTTP methods for disabling modular inputs.

pattern = <string>
* REST path for disabling inputs.

############################################
# HEALTH & DIAGNOSTICS
############################################

[expose:defender_easm_health]
methods = <comma-separated list>
* Allowed HTTP methods for health checks.

pattern = <string>
* REST path for application health endpoint.
