![Microsoft Defender EASM](docs/images/Microsoft_Defender_EASM_logo.PNG)

# Microsoft Defender EASM for Splunk App

## Overview

Microsoft Defender External Attack Surface Management (EASM) for Splunk provides full visibility into an organization’s externally exposed digital footprint using the Microsoft Defender EASM REST APIs.

This Splunk App enables security teams to **discover, monitor, analyze, and operationalize external attack surface data** directly in Splunk—without relying on the Microsoft Defender External Attack Surface Management (EASM) portal User Interface.

---

## Supported Asset Types

Microsoft Defender EASM discovers and tracks the following asset classes:

- Domains
- Hosts
- Pages
- IP Addresses
- IP Blocks
- Autonomous System Numbers (ASNs)
- SSL Certificates
- WHOIS Contacts
- DNS Records

---



![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active%20development-yellow.svg)

---
## Features

### 🛡️ Core Capabilities

| Feature | Description |
|------|-------------|
| 🌐 Asset Discovery | Continuous discovery of internet-facing assets |
| 🧭 Asset Inventory | Unified inventory across all asset types |
| 🔎 Exposure Visibility | Identify exposed infrastructure and services |
| 🧩 Attribution Context | Asset ownership and relationship mapping |
| 🕵️ Change Tracking | Detect newly discovered or modified assets |
| 🧾 Evidence Preservation | Raw API data retained for auditability |

---

### 📈 Analytics & Visibility

| Feature | Description |
|------|-------------|
| 📊 Asset Growth Trends | Track attack surface expansion over time |
| 🔄 Asset Lifecycle | New, existing, and removed asset tracking |
| 🧱 Infrastructure Mapping | Domain → host → IP → ASN relationships |
| 🔐 Certificate Monitoring | SSL certificate inventory and expiration |
| 🧠 Contextual Pivoting | Pivot across assets, ownership, and evidence |

---

### ⚙️ Operational Excellence

| Feature | Description |
|------|-------------|
| 📡 Modular Input Framework | Secure API-based ingestion |
| 🔑 Credential Management | Encrypted credential storage via Splunk |
| 🌐 Proxy Support | Enterprise proxy compatibility |
| 🩺 Health Monitoring | API reachability and ingestion status |
| 📋 Operational Logging | Full ingestion traceability |
| ⏱️ Rate-Limit Awareness | Safe polling and throttling handling |

---

## 📊 Dashboards


| 


---
## Operation Group

| Operation group        | Operation Type | Description                                                                 |
|------------------------|----------------|-----------------------------------------------------------------------------|
| Assets                 | Data plane     | Retrieve or update assets by assetID or designated search parameters.      |
| Data Connections       | Data plane     | Retrieve, create, validate or delete a data connection.                    |
| Discovery groups       | Data plane     | Retrieve, create, run or remove discovery groups, and retrieve discovery results. |
| Discovery templates    | Data plane     | Retrieve discovery templates.                                               |
| Reports                | Data plane     | Retrieve a recent snapshot of asset summary values, or historic summary details. |
| Saved filters          | Data plane     | Retrieve a list of saved filters, or retrieve, create or remove a specific filter. |
| Tasks                  | Data plane     | Retrieve a list of tasks, or retrieve, cancel or download data for a specific taskID. |
| Labels                 | Control plane  | Retrieve labels, or create, update, or delete a label.                     |
| Operations             | Control plane  | Retrieve a list of operations.                                              |
| Workspaces             | Control plane  | Retrieve a list of workspaces by resource group or subscription, or create, update, or delete a specific workspace. |
| Tasks                  | Control plane  | Retrieve tasks submitted in the given workspace.                           |

---

## 🧾 Sourcetypes

The app ingests raw JSON events using the following sourcetypes (as configured in `default/inputs.conf`):

### Core Inventory (Data Plane)
- `defender:easm:domain`
- `defender:easm:host`
- `defender:easm:page`
- `defender:easm:ip_address`
- `defender:easm:ip_block`
- `defender:easm:asn`
- `defender:easm:ssl_certificate`
- `defender:easm:whois_contact`
- `defender:easm:dns_record`

### Exposure / Attack Surface
- `defender:easm:exposure_insight`

### Discovery & Tasking
- `defender:easm:discovery_template`
- `defender:easm:discovery_run`
- `defender:easm:task`

### Data Connections
- `defender:easm:data_connection`
- `defender:easm:data_connection_validation`

### Reporting
- `defender:easm:report`
- `defender:easm:report_output`

### RBAC & Control Plane
- `defender:easm:rbac:role_definition`
- `defender:easm:rbac:role_assignment`
- `defender:easm:workspace`
- `defender:easm:operations`
- `defender:easm:license`

---

## 🧭 Navigation Structure

Navigation matches `default/data/ui/nav/default.xml`:

### Overview
- **Overview**

### Dashboards
- Attack Surface Summary  
- Security Posture  
- GDPR Compliance  
- OWASP Top 10  
- CWE Top 25  
- CISA Known Exploits  
- Trends  
- Operations  
- Health  

### Manage
- Inventory  
- Assets  
- Inventory Changes  
- Discovery  
- Labels  
- Billable Assets  
- Data Connections  
- Data Connection Validation  
- Task Manager  
- Tasks  
- Reports  

### Users
- User Permissions  
- User Activity  
- Privileged Role Activity  

### Platform
- Workspaces  
- Role Definitions  
- Policies  

### Help
- Support & Troubleshooting

## Deployment

### Step 1: Install the App

1. Download `Microsoft_Defender_EASM_For_Splunk_App-1.0.0.tar.gz`
2. In Splunk Web, go to **Apps → Manage Apps**
3. Select **Install app from file**
4. Upload the package
5. Restart Splunk if prompted

---

### Step 2: Configure the App

This app uses a guided setup workflow (`setup.xml`) to ensure secure and AppInspect-compliant configuration.

Navigate to **Apps → Microsoft Defender EASM → Setup** to configure:
- Microsoft Defender EASM API credentials (stored securely)
- Optional enterprise proxy settings
- Modular input enablement and polling intervals

All inputs are **disabled by default** and must be enabled through the setup interface.

#### API Configuration
- Defender EASM API Key
- API Base URL  
  https://api.defender.microsoft.com
- Request Timeout
- Verify SSL Certificates

#### Proxy Configuration (Optional)
- Enable Proxy
- Proxy URL
- Proxy Username
- Proxy Password

#### Data Inputs
- Domains
- Hosts
- Pages
- IP Addresses
- IP Blocks
- ASNs
- SSL Certificates
- WHOIS Contacts
- DNS Records

---

### Step 3: Validate Configuration

- Test API connectivity
- Validate authentication
- Verify permissions
- Automatic validation on first launch

---

### Step 4: Verify Data Collection

Run the following search in Splunk:

    index=security_defender_easm sourcetype=defender:easm:*
    | stats count by sourcetype

---

## 📦 Requirements

- Splunk Enterprise or Splunk Cloud
- Python 3.x (Splunk bundled)
- Microsoft Defender EASM API Access
- Network access to Defender EASM APIs

---

## ✅ AppInspect Compliance

- Proper Splunk directory structure
- No hardcoded credentials
- Inputs disabled by default
- Encrypted credential storage
- app.manifest included
- MIT License
- Setup-based configuration

---

## 🛠️ Troubleshooting

### No Data Appearing
- Verify API key permissions
- Test API connectivity
- Confirm inputs are enabled
- Check Splunk internal logs

### API Errors
- Validate authentication scope
- Check rate limits
- Confirm Defender EASM service availability

### Proxy Issues
- Validate proxy URL and credentials
- Confirm SSL inspection compatibility
- Test proxy connectivity from Splunk

---

## 📚 References

- Defender EASM REST API  
  https://learn.microsoft.com/en-us/rest/api/defenderforeasm/

- Azure Python SDK (Preview)  
  https://learn.microsoft.com/en-us/python/api/overview/azure/defender-easm-readme

- Splunk Documentation  
  https://docs.splunk.com

---

## 📜 License

MIT License 2.0
