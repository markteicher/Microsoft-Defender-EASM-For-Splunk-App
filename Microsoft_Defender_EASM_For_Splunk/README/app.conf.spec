# app.conf.spec
#
# Microsoft Defender EASM for Splunk App
#
# This file documents supported configuration options for app.conf.
# It defines application metadata, UI visibility, and Splunk
# compatibility requirements.
#
# Only documented keys are supported. Additional keys may cause
# AppInspect failures.
#

############################################
# INSTALLATION SETTINGS
############################################

[install]

is_configured = <boolean>
* Indicates whether the app has completed initial configuration.
* Default: false

state = <string>
* Application state.
* Supported values: enabled, disabled

############################################
# USER INTERFACE SETTINGS
############################################

[ui]

is_visible = <boolean>
* Controls whether the app is visible in the Splunk UI.

label = <string>
* Display name of the app in Splunk Web.

description = <string>
* Short description shown in Splunk UI.

############################################
# LAUNCHER METADATA
############################################

[launcher]

author = <string>
* Name of the application author.

description = <string>
* Long description shown in Splunkbase and Splunk UI.

version = <string>
* Application version (semantic versioning recommended).

build = <integer>
* Incremental build number.

visibility = <boolean>
* Controls whether the app is visible in Splunkbase listings.

############################################
# SPLUNK PLATFORM COMPATIBILITY
############################################

[splunk]

minSplunkVersion = <string>
* Minimum supported Splunk version.
* Example: 8.0
