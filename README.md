# Microsoft Defender External Attack Surface Management (EASM) for Splunk App

## Overview

Microsoft Defender External Attack Surface Management (EASM) continuously discovers, inventories, and monitors an organization’s internet-facing attack surface. Defender EASM identifies external assets, tracks exposure changes, and highlights risks introduced by unmanaged or unknown infrastructure.

This Splunk App provides the ability to monitor, investigate, and operationalize Microsoft Defender EASM assets, discoveries, exposure findings, relationships, and platform health using the Microsoft Defender EASM REST APIs.

The app delivers operational and investigative visibility into external attack surface data directly within Splunk, without requiring analysts or engineers to work inside the Microsoft Defender portal.

---

## Microsoft Defender EASM supports the following environments

External Attack Surface Management is cloud-based and applies to:

- Public domains
- IP address ranges
- Certificates
- Web applications
- Cloud-hosted infrastructure
- Third-party and subsidiary assets
- Shadow IT and unmanaged internet-facing services

---

## Features

### 🛡️ Core Capabilities

| Feature | Description |
|---------|-------------|
| 🌐 Asset Discovery | Ingest discovered domains, IPs, hosts, certificates, and services |
| 🔍 Exposure Findings | Collect and analyze externally visible risks and weaknesses |
| 🧬 Asset Relationships | Track relationships between assets, domains, and infrastructure |
| 🧾 Inventory Management | Maintain authoritative external asset inventory |
| 👥 Ownership Attribution | Capture ownership, tags, and metadata when available |
| 🔄 Continuous Discovery | Track newly discovered and changed assets |

### 📈 Advanced Analytics

| Feature | Description |
|---------|-------------|
| 📊 Asset Trending | Track asset growth and reduction over time |
| 📉 Exposure Trending | Monitor exposure trends day-over-day and week-over-week |
| 🧭 Attack Surface Drift | Detect unexpected changes in exposed infrastructure |
| 🔍 Discovery Analysis | Analyze how and when assets were discovered |
| 🧩 Asset Correlation | Correlate assets across IPs, domains, and certificates |

### ⚙️ Operational Excellence

| Feature | Description |
|---------|-------------|
| 📊 Ingestion Metrics | API calls, records ingested, and processing rates |
| 💓 Collection Health | API connectivity and ingestion status |
| ✅ Configuration Validation | Automatic setup validation |
| 🕐 Scheduled Health Checks | Periodic API and credential checks |
| 📋 API Log Visibility | Full API request and error logging |

### 🚀 Deployment

| Feature | Description |
|---------|-------------|
| 📊 Pre-built Dashboards | Immediate insights out of the box |
| 🖥️ Web UI Setup | Configure via Splunk Web |
| ☁️ Splunk Cloud Ready | AppInspect-aligned design |
| 📡 Modular Input | Secure REST API-based ingestion |

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

- **Tenant ID**
- **Client ID**
- **Client Secret**
- **API Base URL**
- **Verify SSL**
- **Request Timeout**

#### Proxy Configuration (Optional)

- **Use Proxy**
- **Proxy URL**
- **Proxy Username**
- **Proxy Password**

#### Data Inputs

- Assets
- Inventory
- Exposure Findings
- Discovery Events
- Asset Relationships
- Platform Health

### Step 3: Validate Configuration

- Test API connectivity
- Automatic validation on first launch

### Step 4: Verify Data Collection

```spl
index=security_defender_easm sourcetype=defender:easm:*
| stats count by sourcetype
