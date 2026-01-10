# restmap.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents REST endpoint mappings used by the
# Microsoft Defender EASM Splunk App.
#
# REST handlers are implemented in Python and are used for:
# - Setup and configuration
# - Validation and connectivity testing
# - Modular input management
# - Health and diagnostics
#
# All endpoints are exposed via web.conf and must match
# the patterns defined here exactly.
#

############################################
# SETUP & CONFIGURATION
############################################

[script:defender_easm_setup]
match = <string>
* REST URL path for setup and configuration.

script = <string>
* Python script handling setup requests.

scripttype = python
* Script language.

python.version = python3
* Python runtime version.

handleractions = edit,list
* Supported REST actions.

[script:defender_easm_setup_reload]
match = <string>
* REST URL path for reloading configuration.

script = <string>
* Python script handling reload requests.

scripttype = python

python.version = python3

handleractions = reload
* Supported REST actions.

############################################
# VALIDATION & CONNECTIVITY
############################################

[script:defender_easm_validate]
match = <string>
* REST URL path for configuration validation.

script = <string>
* Python script handling validation requests.

scripttype = python

python.version = python3

handleractions = list
* Supported REST actions.

[script:defender_easm_test_connection]
match = <string>
* REST URL path for testing connectivity.

script = <string>
* Python script handling connectivity tests.

scripttype = python

python.version = python3

handleractions = list
* Supported REST actions.

############################################
# MODULAR INPUT MANAGEMENT
############################################

[script:defender_easm_inputs]
match = <string>
* REST URL path for listing modular inputs.

script = <string>
* Python script handling input listing.

scripttype = python

python.version = python3

handleractions = list
* Supported REST actions.

[script:defender_easm_inputs_status]
match = <string>
* REST URL path for retrieving modular input status.

script = <string>
* Python script handling input status queries.

scripttype = python

python.version = python3

handleractions = list
* Supported REST actions.

[script:defender_easm_inputs_enable]
match = <string>
* REST URL path for enabling modular inputs.

script = <string>
* Python script handling enable operations.

scripttype = python

python.version = python3

handleractions = edit
* Supported REST actions.

[script:defender_easm_inputs_disable]
match = <string>
* REST URL path for disabling modular inputs.

script = <string>
* Python script handling disable operations.

scripttype = python

python.version = python3

handleractions = edit
* Supported REST actions.

############################################
# HEALTH & DIAGNOSTICS
############################################

[script:defender_easm_health]
match = <string>
* REST URL path for health diagnostics.

script = <string>
* Python script handling health checks.

scripttype = python

python.version = python3

handleractions = list
* Supported REST actions.

############################################
# BACKFILL & REPLAY (FUTURE-SAFE)
############################################

[script:defender_easm_backfill]
match = <string>
* REST URL path reserved for backfill and replay operations.

script = <string>
* Python script handling backfill requests.

scripttype = python

python.version = python3

handleractions = edit
* Supported REST actions.
