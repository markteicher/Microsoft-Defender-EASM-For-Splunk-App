# Microsoft Defender EASM for Splunk App

## Overview

Microsoft Defender External Attack Surface Management (EASM) for Splunk provides full visibility into your organization’s externally exposed digital footprint using the Microsoft Defender EASM REST APIs.

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
| 🌍 Geographic Analysis | Country and ASN-based exposure insights |
| 🧠 Contextual Pivoting | Pivot across assets, ownership, and evidence |

---

### ⚙️ Operational Excellence

| Feature | Description |
|------|-------------|
| 📡 Modular Input Framework | Secure API-based ingestion |
| 🔑 API Key Management | Encrypted credential storage |
| 🌐 Proxy Support | Enterprise proxy compatibility |
| 🩺 Health Monitoring | API reachability and ingestion status |
| 📋 Operational Logging | Full API and ingestion traceability |
| ⏱️ Rate-Limit Awareness | Safe polling and throttling handling |

---

## 🧭 Navigation Structure

### 📁 General
- **Inventory**

---

### 📊 Dashboards
- **Attack Surface Summary**
- **Security Posture**
- **GDPR Compliance**
- **OWASP Top 10**

---

### 🛠️ Manage
- **Discovery**
- **Labels**
- **Billable Assets**
- **Data Connections**
- **Task Manager**

---

### 👥 Users
- **User Permissions**

---

### ❓ Help
- **Support & Troubleshooting**

## 📊 Overview

### 🔢 Top Summary Metrics

| Position | Metric |
|--------|--------|
| 1 | **Count of Domains** |
| 2 | **Count of Hosts** |
| 3 | **Count of Pages** |
| 4 | **Count of SSL Certificates** |
| 5 | **Count of ASNs** |
| 6 | **Count of IP Blocks** |
| 7 | **Count of IP Addresses** |
| 8 | **Count of Contacts** |

---

### 📌 Attack Surface Insights

| Priority Level | Metric |
|---------------|--------|
| **High Priority** | Count of High Priority |
| **Medium Priority** | Count of Medium Priority |
| **Low Priority** | Count of Low Priority |

## Deployment

### Step 1: Install the App

1. Download `Microsoft_Defender_EASM_For_Splunk_App-1.0.0.tar.gz`
2. In Splunk Web, go to **Apps → Manage Apps**
3. Select **Install app from file**
4. Upload the package
5. Restart Splunk if prompted

---

### Step 2: Configure the App

Navigate to **Apps → Microsoft Defender EASM → Setup**

#### API Configuration
- **Defender EASM API Key**
- **API Base URL**  
  `https://api.defender.microsoft.com`
- **Request Timeout**
- **Verify SSL Certificates**

#### Proxy Configuration (Optional)
- Enable Proxy
- Proxy URL
- Proxy Username
- Proxy Password

#### Data Inputs
- Assets
- Domains
- Hosts
- Pages
- IP Addresses
- IP Blocks
- ASNs
- SSL Certificates
- WHOIS Contacts

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

## 📊 Dashboards

| Dashboard | Description |
|---------|-------------|
| 🌐 Overview | High-level external exposure summary |
| 🧭 Asset Inventory | Complete asset inventory by type |
| 🧱 Infrastructure Map | Domain, host, IP, ASN relationships |
| 🔐 Certificates | SSL certificate monitoring |
| 🌍 Geography | Asset distribution by country and ASN |
| 📈 Trends | Asset growth and change trends |
| ⚙️ Operations | Ingestion metrics and health |
| ❤️ Health | API and data freshness monitoring |

---

## 🧾 Sourcetypes

| Sourcetype | Description |
|-----------|-------------|
| `defender:easm:assets` | Unified asset records |
| `defender:easm:domains` | Domain assets |
| `defender:easm:hosts` | Host assets |
| `defender:easm:pages` | Web page assets |
| `defender:easm:ip_addresses` | IP address assets |
| `defender:easm:ip_blocks` | IP block assets |
| `defender:easm:asns` | Autonomous System Numbers |
| `defender:easm:certificates` | SSL certificates |
| `defender:easm:whois` | WHOIS contact data |
| `defender:easm:health` | Collection health |

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
- `app.manifest` included
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
