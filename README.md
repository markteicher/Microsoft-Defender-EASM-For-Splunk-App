# Microsoft Defender EASM for Splunk App

## Overview

Microsoft Defender External Attack Surface Management (EASM) provides continuous discovery, inventory, classification, and risk analysis of an organization’s external-facing assets.

The **Microsoft Defender EASM for Splunk App** is a full Splunk application that ingests Defender EASM data via the Microsoft REST APIs and enables security teams to monitor external assets, exposure findings, discovery activity, relationships, and platform health directly within Splunk.

This app eliminates the need to rely on the Defender portal UI by operationalizing EASM data for investigation, trending, and correlation inside Splunk.

---

## Features

### 🛡️ Core Capabilities

| Feature | Description |
|--------|------------|
| 🌐 External Asset Inventory | Full visibility into discovered internet-facing assets |
| ⚠️ Exposure Findings | Ingest and analyze exposure findings |
| 🔍 Asset Discovery | Track newly discovered and changed assets |
| 🔗 Relationship Mapping | Asset-to-asset relationship intelligence |
| 📊 Exposure Context | Inventory metadata and classification |
| ❤️ Platform Health | API and ingestion health monitoring |

### 📈 Analytics & Visibility

| Feature | Description |
|--------|------------|
| 📉 Exposure Trending | Exposure and asset trends over time |
| 🧭 Asset Relationships | Understand asset dependencies |
| 🧠 Inventory Enrichment | Metadata-driven asset context |
| ⏱️ Discovery Velocity | New and changed asset discovery rates |
| 📊 Executive Overview | External attack surface summary |

### ⚙️ Operational Excellence

| Feature | Description |
|--------|------------|
| 📊 Ingestion Metrics | API calls, record counts, and rates |
| 💓 Collection Health | Data freshness and API connectivity |
| ✅ Configuration Validation | Automated setup validation |
| 🕐 Scheduled Health Checks | Periodic API and token validation |
| 📋 API Log Visibility | Full API activity logging |

---

## Installation

### Step 1: Deploy the App

1. Download the `Microsoft_Defender_EASM_For_Splunk_App-1.0.0.tar.gz`
2. In Splunk Web, navigate to **Apps → Manage Apps**
3. Click **Install app from file**
4. Upload the `.tar.gz` file
5. Restart Splunk if prompted

### Step 2: Configure the App

1. Navigate to **Apps → Microsoft Defender EASM → Setup**
2. Configure the following settings

#### API Configuration

- **Azure Tenant ID**
- **Azure Client ID**
- **Azure Client Secret**
- **API Base URL**: https://api.securitycenter.microsoft.com
- **Verify SSL**
- **Request Timeout**

#### Proxy Configuration (Optional)

- **Use Proxy**
- **Proxy URL**
- **Proxy Username**
- **Proxy Password**

#### Data Inputs

- Assets
- Inventory Metadata
- Exposure Findings
- Discovery Events
- Relationships
- Platform Health

### Step 3: Validate Configuration

- Test API credentials
- Automatic validation on first launch

### Step 4: Verify Data Collection

Run this search:

    index=security_defender_easm sourcetype=defender:easm:*
    | stats count by sourcetype

---

## 📊 Dashboards

| Dashboard | Description |
|----------|-------------|
| 🧭 Overview | Executive view of external attack surface |
| 🌐 Assets | External asset inventory |
| ⚠️ Findings | Exposure findings |
| 🔎 Discovery | New and changed asset discovery |
| 🔗 Relationships | Asset relationship mapping |
| 📈 Trending | Asset and exposure trends |
| ⚙️ Operations | Ingestion metrics |
| ❤️ Health | API and collection health |

---

## 🧾 Sourcetypes

| Sourcetype | Description |
|-----------|-------------|
| defender:easm:assets | External assets |
| defender:easm:inventory | Inventory metadata |
| defender:easm:findings | Exposure findings |
| defender:easm:discovery | Discovery events |
| defender:easm:relationships | Asset relationships |
| defender:easm:health | Platform health |

---

## 📦 Requirements

- Splunk Enterprise or Splunk Cloud
- Python 3.x (Splunk bundled)
- Microsoft Defender EASM subscription
- Azure AD application credentials

---

## 🛠️ Troubleshooting

- Verify Azure AD credentials
- Test API connectivity
- Review Splunk internal logs
- Confirm index permissions

---

## 📚 Support

- Microsoft Defender EASM API Documentation:  
  https://learn.microsoft.com/en-us/rest/api/defenderforeasm/
- Splunk Documentation:  
  https://docs.splunk.com

---

## 📜 License

Apache License 2.0
