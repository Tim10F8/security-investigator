---
name: exposure-investigation
description: 'Use this skill when asked to generate a vulnerability and exposure management report, assess security posture, or review CVEs, security configurations, and attack paths. Triggers on keywords like "vulnerability report", "exposure report", "CVE assessment", "security posture", "vulnerability assessment", "exposure management", "patch status", "end of support", "security recommendations", "attack paths", "critical assets", "configuration compliance", "Defender device health", "security score", "TVM", "threat and vulnerability management", or when asking about overall organizational vulnerability/exposure state. This skill queries DeviceTvm* tables and ExposureGraphNodes/Edges to produce a comprehensive posture report covering CVEs, exploitable vulnerabilities, security configuration compliance, end-of-support software, critical asset inventory, attack paths, Defender device health, and certificate status. Supports org-wide and per-device scoping with inline chat and markdown file output.'
---

# Vulnerability & Exposure Management Report — Instructions

## Purpose

This skill generates a comprehensive **Vulnerability & Exposure Management Report** covering the full security posture of the organization (or a specific device). It goes beyond CVEs to include security configuration compliance, end-of-support software, Exposure Management critical assets, attack paths, and certificate status.

**Entity Type:** Organization-wide (default) or single device

| Scope | Primary Tables | Use Case |
|-------|----------------|----------|
| Org-wide (default) | `DeviceTvmSoftwareVulnerabilities`, `ExposureGraphNodes`, `ExposureGraphEdges` | Full organizational posture assessment |
| Per-device | `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSecureConfigurationAssessment` | Focused device vulnerability review |

**What this skill covers:**

| Section | Data Source | Coverage |
|---------|-------------|----------|
| CVE Vulnerabilities | `DeviceTvmSoftwareVulnerabilities` + `DeviceTvmSoftwareVulnerabilitiesKB` | Severity distribution, exploitable CVEs, CVSS scores |
| Security Configuration | `DeviceTvmSecureConfigurationAssessment` + `...KB` | OS, Network, Security Controls, Accounts, Application compliance |
| End-of-Support Software | `DeviceTvmSoftwareInventory` | EoS/EoL software with dates and affected devices |
| Critical Assets | `ExposureGraphNodes` | Criticality levels, internet-facing, RCE/privesc flags |
| Attack Paths | `ExposureGraphEdges` + `ExposureGraphNodes` | Multi-hop paths from vulnerable to critical assets |
| Defender Device Health | `DeviceTvmSecureConfigurationAssessment` + `DeviceInfo` | AV mode, signatures, RTP, tamper protection, cloud protection compliance by active/inactive status |
| Certificate Status | `DeviceTvmCertificateInfo` | Expired and expiring certificates |

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
3. **[Quick Start](#quick-start-tldr)** - 8-step execution pattern
4. **[Execution Workflow](#execution-workflow)** - Complete phased process
5. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns (Queries 1-11, 13-15)
6. **[Report Template](#report-template)** - Output structure and formatting
7. **[Per-Device Mode](#per-device-mode)** - Single device scoping
8. **[Known Pitfalls](#known-pitfalls)** - Edge cases
9. **[Error Handling](#error-handling)** - Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY vulnerability/exposure report:**

1. **ALL queries in this skill use `RunAdvancedHuntingQuery`** — DeviceTvm* and ExposureGraph* tables are Advanced Hunting only (NOT in Sentinel Data Lake)
2. **No Sentinel workspace selection is required** — this skill does NOT query Sentinel Data Lake tables
3. **ALWAYS ask the user for output mode** if not specified: inline chat summary, markdown file report, or both (default: both)
4. **ALWAYS ask the user for scope** if ambiguous: org-wide (default) or specific device name
5. **ALWAYS run independent queries in parallel** for performance
6. **ALWAYS use `create_file` for markdown reports** (NEVER use PowerShell terminal commands)
7. **ALWAYS sanitize PII** from saved reports — use generic placeholders for real hostnames, tenant names, and UPNs in committed files (reports/ files for user's own use may contain real values)
8. **ExposureGraph tables are snapshot data** — no `Timestamp` or `TimeGenerated` filter needed
9. **DeviceTvm tables use `Timestamp`** — filter with `Timestamp > ago(1d)` for latest assessment snapshot

### Tool Selection

| Table Pattern | Tool | Notes |
|---------------|------|-------|
| `DeviceTvm*` | `RunAdvancedHuntingQuery` | AH-only tables |
| `ExposureGraphNodes` | `RunAdvancedHuntingQuery` | AH-only, snapshot data, no timestamp filter |
| `ExposureGraphEdges` | `RunAdvancedHuntingQuery` | AH-only, snapshot data, no timestamp filter |

**🔴 PROHIBITED:**
- ❌ Using `mcp_sentinel-data_query_lake` for any table in this skill
- ❌ Adding `TimeGenerated` filters to ExposureGraph queries
- ❌ Reporting findings without actual query evidence
- ❌ Fabricating CVE IDs, CVSS scores, or device names

---

## Output Modes

### Mode 1: Inline Chat Summary (default for quick requests)
Compact executive summary rendered directly in chat.

### Mode 2: Markdown File Report
Full detailed report saved to `reports/exposure/vulnerability_exposure_report_<YYYYMMDD_HHMMSS>.md`.

### Mode 3: Both (default when user says "report" or "generate report")
Inline chat executive summary + full markdown file.

**Ask user if not specified:**
> "How would you like the report? I can provide:
> 1. **Inline chat summary** — executive overview in chat
> 2. **Markdown file** — detailed report saved to reports/exposure/
> 3. **Both** (recommended) — summary in chat + full report file"

---

## Quick Start (TL;DR)

**8-step execution pattern for org-wide report:**

```
Step 1: Determine scope (org-wide or specific device) and output mode
Step 2: Run Phase 1 queries in parallel — CVE distribution, exploitable CVEs, config compliance
Step 3: Run Phase 2 queries in parallel — EoS software, per-device vulns, per-device compliance
Step 4: Run Phase 3 queries in parallel — ExposureGraph critical assets, high-impact misconfigs, Defender health fleet summary
Step 5: Run Phase 4 queries in parallel — Attack paths, Defender health exceptions, certificates
Step 6: Run Phase 5 (optional) — Top vulnerable software, internet-facing critical assets
Step 7: Compute summary metrics and risk assessment
Step 8: Render inline chat executive summary
Step 9: Generate markdown file report (if requested)
```

---

## Execution Workflow

### Phase 1: Core Vulnerability & Compliance (3 parallel queries)

Run these simultaneously:

| Query | Description | Reference |
|-------|-------------|-----------|
| **Q1** | CVE severity distribution | [Query 1](#query-1-cve-severity-distribution) |
| **Q2** | Exploitable CVEs (with known exploits) | [Query 2](#query-2-exploitable-cves) |
| **Q3** | Security config compliance by category | [Query 3](#query-3-security-config-compliance-by-category) |

### Phase 2: Software & Per-Device Detail (3 parallel queries)

| Query | Description | Reference |
|-------|-------------|-----------|
| **Q4** | End-of-support software inventory | [Query 4](#query-4-end-of-support-software) |
| **Q5** | Per-device vulnerability counts | [Query 5](#query-5-per-device-vulnerability-counts) |
| **Q6** | Per-device compliance scorecard | [Query 6](#query-6-per-device-compliance-scorecard) |

### Phase 3: Exposure Management & Defender Health (3 parallel queries)

| Query | Description | Reference |
|-------|-------------|----------|
| **Q7** | Critical asset inventory | [Query 7](#query-7-critical-asset-inventory) |
| **Q8** | High-impact misconfigurations with remediation | [Query 8](#query-8-high-impact-misconfigurations) |
| **Q9** | Defender health fleet summary | [Query 9](#query-9-defender-health-fleet-summary) |

### Phase 4: Attack Paths & Supplementary (4 parallel queries)

| Query | Description | Reference |
|-------|-------------|----------|
| **Q10a** | Vulnerable device exposure summary (fast) | [Query 10a](#query-10a-vulnerable-device-exposure-summary) |
| **Q10b** | Edge connectivity from vulnerable devices (fast) | [Query 10b](#query-10b-edge-connectivity-from-vulnerable-devices) |
| **Q11** | Defender health non-compliant exceptions | [Query 11](#query-11-defender-health-non-compliant-exceptions) |
| **Q13** | Certificate expiration status | [Query 13](#query-13-certificate-expiration-status) |

### Phase 5: Supplementary Detail (optional, 3 parallel queries)

Run only if Phase 1-4 reveal high-risk items:

| Query | Description | Reference |
|-------|-------------|-----------|
| **Q14** | Top vulnerable software by CVE count | [Query 14](#query-14-top-vulnerable-software) |
| **Q15** | Internet-facing critical assets with vulnerabilities | [Query 15](#query-15-internet-facing-critical-assets-with-vulnerabilities) |
| **Q16** | Multi-hop attack path enumeration (slow — graph-match) | [Query 16](#query-16-multi-hop-attack-path-enumeration) |

### Phase 6: Render Output

1. Compute summary metrics from all query results
2. Assign overall risk rating (see [Risk Assessment](#risk-assessment))
3. Render inline chat executive summary
4. Generate markdown file (if requested)

---

## Sample KQL Queries

> **All queries use `RunAdvancedHuntingQuery`** via the Sentinel Triage MCP server.

### Query 1: CVE Severity Distribution

```kql
DeviceTvmSoftwareVulnerabilities
| summarize 
    DeviceCount = dcount(DeviceId),
    VulnCount = count()
    by VulnerabilitySeverityLevel
| order by VulnCount desc
```

**Purpose:** Top-level severity breakdown for executive summary.

---

### Query 2: Exploitable CVEs

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where IsExploitAvailable == true
| summarize 
    AffectedDevices = dcount(DeviceName),
    DeviceList = make_set(DeviceName)
    by CveId, VulnerabilitySeverityLevel, CvssScore, VulnerabilityDescription
| order by CvssScore desc, AffectedDevices desc
| take 20
```

**Purpose:** Highest-risk CVEs — known exploits mean active threat. These are always Priority 1.

---

### Query 3: Security Config Compliance by Category

```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(1d)
| summarize 
    TotalAssessments = count(),
    CompliantCount = countif(IsCompliant == true),
    NonCompliantCount = countif(IsCompliant == false)
    by ConfigurationCategory
| extend ComplianceRate = round(100.0 * CompliantCount / TotalAssessments, 1)
| order by NonCompliantCount desc
```

**Purpose:** Compliance posture across OS, Network, Security Controls, Accounts, Application categories.

---

### Query 4: End-of-Support Software

```kql
DeviceTvmSoftwareInventory
| where EndOfSupportStatus != ""
| summarize 
    AffectedDevices = dcount(DeviceId),
    DeviceList = make_set(DeviceName)
    by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate
| order by AffectedDevices desc
```

**Purpose:** Identify unsupported software — no patches available, high risk.

**EndOfSupportStatus values:**
- `EOS Software` — Entire product line end-of-support
- `EOS Version` — Specific version end-of-support
- `Upcoming EOS Version` — EoS within next 6 months

---

### Query 5: Per-Device Vulnerability Counts

```kql
DeviceTvmSoftwareVulnerabilities
| summarize 
    Critical = countif(VulnerabilitySeverityLevel == "Critical"),
    High = countif(VulnerabilitySeverityLevel == "High"),
    Medium = countif(VulnerabilitySeverityLevel == "Medium"),
    Low = countif(VulnerabilitySeverityLevel == "Low"),
    Total = count()
    by DeviceName, OSPlatform
| order by Critical desc, High desc, Total desc
```

**Purpose:** Per-device vulnerability heatmap — identifies most vulnerable endpoints.

---

### Query 6: Per-Device Compliance Scorecard

```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(1d)
| summarize 
    TotalChecks = count(),
    Compliant = countif(IsCompliant == true),
    NonCompliant = countif(IsCompliant == false),
    NotApplicable = countif(IsApplicable == false)
    by DeviceName
| extend ComplianceRate = round(100.0 * Compliant / (Compliant + NonCompliant), 1)
| order by ComplianceRate asc
```

**Purpose:** Rank devices by compliance rate — worst-first for remediation priority.

---

### Query 7: Critical Asset Inventory

> **🔴 MCP Property Access:** `NodeProperties` is stored as a JSON string. Direct dot-notation (`NodeProperties.rawData.criticalityLevel`) returns null through MCP serialization. MUST use double `parse_json(tostring())` extraction — see [Known Pitfalls](#known-pitfalls).

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| extend critLevel = rawData.criticalityLevel
| extend critValue = toint(critLevel.criticalityLevel)
| extend ruleBasedCrit = toint(critLevel.ruleBasedCriticalityLevel)
| extend ruleNames = tostring(critLevel.ruleNames)
| where isnotnull(critLevel) and critValue < 4
| extend InternetFacing = iff(isnotnull(rawData.IsInternetFacing), "Yes", "No")
| extend VulnerableToRCE = iff(isnotnull(rawData.vulnerableToRCE), "Yes", "No")
| extend VulnerableToPrivEsc = iff(isnotnull(rawData.VulnerableToPrivilegeEscalation), "Yes", "No")
| extend ExposureScore = tostring(rawData.exposureScore)
| project 
    DeviceName = NodeName,
    CriticalityLevel = critValue,
    RuleBasedCriticality = ruleBasedCrit,
    RuleNames = ruleNames,
    InternetFacing,
    VulnerableToRCE,
    VulnerableToPrivEsc,
    ExposureScore,
    NodeLabel
| order by CriticalityLevel asc
```

**Purpose:** Inventory critical assets with exposure flags — feeds into prioritization.

**Criticality Levels:**
- **0-1**: Most critical (domain controllers, high-value servers)
- **2-3**: High priority
- **4+**: Standard (excluded from this query)

> **Note on zero results:** If this query returns 0 results, it means no devices have criticality classifications. Check the raw `NodeProperties` with `ExposureGraphNodes | where set_has_element(Categories, "device") | extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData)) | project NodeName, rawData | take 5` to verify property structure. Criticality is auto-assigned for domain controllers (Level 0) and can be manually assigned in the Exposure Management portal.

---

### Query 8: High-Impact Misconfigurations

```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(1d)
| where IsCompliant == false and IsApplicable == true
| summarize AffectedDevices = dcount(DeviceId), DeviceList = make_set(DeviceName) by ConfigurationId
| join kind=inner DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| project 
    ConfigurationId,
    ConfigurationName,
    ConfigurationCategory,
    ConfigurationSubcategory,
    ConfigurationImpact,
    RiskDescription,
    RemediationOptions,
    AffectedDevices,
    DeviceList
| order by ConfigurationImpact desc, AffectedDevices desc
| take 20
```

**Purpose:** Top misconfigurations ranked by impact score with actionable remediation steps from the KB.

**ConfigurationImpact scores:**
- **9-10**: Critical — must remediate immediately
- **7-8**: High — remediate in short term
- **4-6**: Medium — plan remediation
- **1-3**: Low — monitor

---

### Query 9: Defender Health Fleet Summary

```kql
// Defender Health Fleet Summary — compliance by control × OS × active/inactive status
// Active = DeviceInfo last seen within 7 days; Inactive = last seen > 7 days ago
// SCID Mapping:
//   Windows: scid-2010 (AVMode), scid-2011 (AVSignatures), scid-2012 (RTP),
//            scid-2013 (PUA), scid-2016 (CloudProtection), scid-2003 (TamperProtection),
//            scid-91 (BehaviourMonitoring), scid-2030 (CoreComponentsUpdate)
//   macOS:   scid-5090 (RTP), scid-5091 (PUA), scid-5094 (Cloud), scid-5095 (AVSigs)
//   Linux:   scid-6090 (RTP), scid-6091 (PUA), scid-6094 (Cloud), scid-6095 (AVSigs)
let defenderSCIDs = dynamic([
    "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2016", 
    "scid-2003", "scid-91", "scid-2030",
    "scid-5090", "scid-5091", "scid-5094", "scid-5095",
    "scid-6090", "scid-6091", "scid-6094", "scid-6095"
]);
let deviceStatus = DeviceInfo
| summarize arg_max(Timestamp, DeviceName, OSPlatform) by DeviceId
| extend DeviceActivity = iff(Timestamp > ago(7d), "Active", "Inactive");
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in~ (defenderSCIDs)
| where IsApplicable == 1
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| extend Control = case(
    ConfigurationId =~ "scid-2010", "AVMode",
    ConfigurationId =~ "scid-2011", "AVSignatures",
    ConfigurationId =~ "scid-2012", "RealtimeProtection",
    ConfigurationId =~ "scid-2013", "PUAProtection",
    ConfigurationId =~ "scid-2016", "CloudProtection",
    ConfigurationId =~ "scid-2003", "TamperProtection",
    ConfigurationId =~ "scid-91", "BehaviourMonitoring",
    ConfigurationId =~ "scid-2030", "CoreComponentsUpdate",
    ConfigurationId =~ "scid-5090", "RealtimeProtection",
    ConfigurationId =~ "scid-5091", "PUAProtection",
    ConfigurationId =~ "scid-5094", "CloudProtection",
    ConfigurationId =~ "scid-5095", "AVSignatures",
    ConfigurationId =~ "scid-6090", "RealtimeProtection",
    ConfigurationId =~ "scid-6091", "PUAProtection",
    ConfigurationId =~ "scid-6094", "CloudProtection",
    ConfigurationId =~ "scid-6095", "AVSignatures",
    ConfigurationId)
| join kind=leftouter deviceStatus on DeviceId
| extend DeviceActivity = coalesce(DeviceActivity, "Unknown")
| summarize
    Compliant = countif(IsCompliant == 1),
    NonCompliant = countif(IsCompliant == 0),
    TotalDevices = dcount(DeviceId)
    by Control, OSPlatform, DeviceActivity
| extend ComplianceRate = round(100.0 * Compliant / (Compliant + NonCompliant), 1)
| order by DeviceActivity asc, Control asc, OSPlatform asc
```

**Purpose:** Fleet-scale Defender for Endpoint health dashboard. Shows compliance rates for each security control by OS platform, split by active/inactive device status. Designed for environments with 1000+ devices — does NOT list individual devices.

**Defender Controls Assessed:**

| Control | Description | Critical? |
|---------|-------------|----------|
| AVMode | Antivirus running in Active mode (vs Passive/EDR Blocked) | 🔴 Yes |
| AVSignatures | Antivirus signature definitions are current | 🟠 High |
| RealtimeProtection | Real-time file scanning enabled | 🔴 Yes |
| PUAProtection | Potentially Unwanted Application blocking enabled | 🟡 Medium |
| CloudProtection | Cloud-delivered protection (MAPS) enabled | 🟠 High |
| TamperProtection | Tamper Protection prevents disabling security settings | 🔴 Yes |
| BehaviourMonitoring | Behavioral analysis and monitoring enabled | 🟠 High |
| CoreComponentsUpdate | MDE unified agent / core components current | 🟡 Medium |

**Active vs Inactive Classification:**
- **Active**: Device last seen in `DeviceInfo` within 7 days — these are operational endpoints
- **Inactive**: Device last seen > 7 days ago — stale signature data is expected and should NOT be flagged as a security gap

> **Interpretation guidance:** Focus on active devices with non-compliant critical controls (AVMode, RTP, TamperProtection). Inactive devices with stale AVSignatures are expected — report as "X inactive devices not reporting" rather than "X devices with outdated signatures."

> **SCID reference:** Based on [Jeffrey Appel's Defender health guide](https://jeffreyappel.nl/how-to-check-for-a-healthy-defender-for-endpoint-environment/) and [Azure/Azure-Sentinel MDE_DeviceHealth.YAML](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/Microsoft%20365%20Defender/General%20queries/MDE_DeviceHealth.yaml).

---

### Query 10a: Vulnerable Device Exposure Summary

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| extend HasHighCritVulns = isnotnull(rawData.highRiskVulnerabilityInsights) 
    and tostring(parse_json(tostring(rawData.highRiskVulnerabilityInsights)).hasHighOrCritical) == "true"
| extend VulnerableToRCE = isnotnull(rawData.vulnerableToRCE)
| extend VulnerableToPrivEsc = isnotnull(rawData.VulnerableToPrivilegeEscalation)
| extend InternetFacing = isnotnull(rawData.IsInternetFacing)
| extend critLevel = rawData.criticalityLevel
| extend IsCritical = isnotnull(critLevel) and toint(critLevel.criticalityLevel) < 4
| summarize 
    TotalDevices = count(),
    HighCritVulnDevices = countif(HasHighCritVulns),
    RCEVulnDevices = countif(VulnerableToRCE),
    PrivEscVulnDevices = countif(VulnerableToPrivEsc),
    InternetFacingDevices = countif(InternetFacing),
    InternetFacingWithHighCritVulns = countif(InternetFacing and HasHighCritVulns),
    CriticalDevices = countif(IsCritical),
    CriticalWithHighCritVulns = countif(IsCritical and HasHighCritVulns)
```

**Purpose:** Fast single-table scan that produces executive-level exposure headlines:
- "X of Y devices have high/critical vulnerabilities"
- "Z internet-facing devices are vulnerable"
- "N critical assets have exploitable weaknesses"

> **Performance:** ⚡ Fast — single ExposureGraphNodes scan, no graph-match. Always runs in <5 seconds.

> **Key property:** `highRiskVulnerabilityInsights.hasHighOrCritical` is the reliable vulnerability flag on device nodes. The property is a nested JSON string requiring `parse_json(tostring(...))` to extract. See `queries/cloud/exposure_graph_attack_paths.md` Node Property Reference for full details.

---

### Query 10b: Edge Connectivity from Vulnerable Devices

```kql
let VulnDevices = ExposureGraphNodes
| where set_has_element(Categories, "device")
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| where isnotnull(rawData.highRiskVulnerabilityInsights)
| extend HasHighCritVulns = tostring(parse_json(tostring(rawData.highRiskVulnerabilityInsights)).hasHighOrCritical) == "true"
| where HasHighCritVulns
| project NodeId;
let TargetNodes = ExposureGraphNodes
| project NodeId, TargetName = NodeName, TargetCategories = Categories, TargetLabel = NodeLabel;
ExposureGraphEdges
| join kind=inner VulnDevices on $left.SourceNodeId == $right.NodeId
| join kind=inner TargetNodes on $left.TargetNodeId == $right.NodeId
| extend TargetType = case(
    set_has_element(TargetCategories, "identity"), "Identity",
    set_has_element(TargetCategories, "compute"), "Compute",
    set_has_element(TargetCategories, "data"), "Data Store",
    set_has_element(TargetCategories, "ip_address"), "IP Address",
    tostring(TargetCategories))
| summarize 
    PathCount = count(),
    UniqueTargets = dcount(TargetNodeId),
    SampleTargets = make_set(TargetName, 5)
    by EdgeLabel, TargetType
| order by PathCount desc
```

**Purpose:** Shows the 1-hop blast radius shape from vulnerable devices WITHOUT expensive `graph-match`. Reveals:
- How many identities can be reached (lateral movement risk)
- How many Azure resources are reachable (data exfiltration risk)
- Which edge types dominate (authentication vs permissions vs network)

> **Performance:** ⚡ Fast — join-based aggregation, no `make-graph` or `graph-match`. Runs in <10 seconds even on large graphs.

> **Interpretation:** High counts on "can authenticate as" edges to identities indicate lateral movement risk. High counts on "has permissions to" edges to data stores indicate data exfiltration risk. Feed the most concerning edge types into Q16 (optional deep-dive) if needed.

> **Portal deep-dive:** For interactive multi-hop attack path exploration, use the [Exposure Management Attack Paths portal](https://security.microsoft.com/exposure-management/attack-paths).

---

### Query 11: Defender Health Non-Compliant Exceptions

```kql
// Defender Health Non-Compliant Exceptions — exception-based, active devices only
// Groups non-compliant controls per device for fleet-scale readability
// Inactive devices excluded — stale signatures on offline devices are expected
let defenderSCIDs = dynamic([
    "scid-2010", "scid-2011", "scid-2012", "scid-2013", "scid-2016", 
    "scid-2003", "scid-91", "scid-2030",
    "scid-5090", "scid-5091", "scid-5094", "scid-5095",
    "scid-6090", "scid-6091", "scid-6094", "scid-6095"
]);
let deviceStatus = DeviceInfo
| summarize arg_max(Timestamp, DeviceName, OSPlatform) by DeviceId
| extend DeviceActivity = iff(Timestamp > ago(7d), "Active", "Inactive"),
         LastSeen = Timestamp;
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in~ (defenderSCIDs)
| where IsApplicable == 1
| where IsCompliant == 0
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| extend Control = case(
    ConfigurationId =~ "scid-2010", "AVMode",
    ConfigurationId =~ "scid-2011", "AVSignatures",
    ConfigurationId =~ "scid-2012", "RealtimeProtection",
    ConfigurationId =~ "scid-2013", "PUAProtection",
    ConfigurationId =~ "scid-2016", "CloudProtection",
    ConfigurationId =~ "scid-2003", "TamperProtection",
    ConfigurationId =~ "scid-91", "BehaviourMonitoring",
    ConfigurationId =~ "scid-2030", "CoreComponentsUpdate",
    ConfigurationId =~ "scid-5090", "RealtimeProtection",
    ConfigurationId =~ "scid-5091", "PUAProtection",
    ConfigurationId =~ "scid-5094", "CloudProtection",
    ConfigurationId =~ "scid-5095", "AVSignatures",
    ConfigurationId =~ "scid-6090", "RealtimeProtection",
    ConfigurationId =~ "scid-6091", "PUAProtection",
    ConfigurationId =~ "scid-6094", "CloudProtection",
    ConfigurationId =~ "scid-6095", "AVSignatures",
    ConfigurationId)
| join kind=inner deviceStatus on DeviceId
| where DeviceActivity == "Active"
| summarize 
    NonCompliantControls = make_set(Control),
    FailedCount = dcount(Control),
    HighestImpact = max(toreal(ConfigurationImpact))
    by DeviceName, OSPlatform, LastSeen
| order by FailedCount desc, HighestImpact desc
| take 100
```

**Purpose:** Exception-based reporting — only surfaces active devices failing Defender health controls. Groups all non-compliant controls per device for fleet-scale readability (one row per problem device, not one row per failed check).

**Design for scale:**
- **Inner join** with `DeviceInfo` → only active devices (seen within 7 days)
- **Summarize by device** → one row per device listing all failed controls as an array
- **`take 100`** → practical limit for very large environments; increase if needed
- **Inactive devices excluded** → stale signatures on offline devices are expected, not actionable

> **Note:** If this query returns 0 results, that's a positive finding — report as "✅ All active devices pass all Defender health controls." If the fleet summary (Q9) shows non-compliant devices but all are Inactive, report as: "⚠️ X inactive devices have stale Defender configurations — verify if devices should be decommissioned or reconnected."

---

### Query 13: Certificate Expiration Status

> **🔴 CRITICAL:** `DeviceTvmCertificateInfo` does **NOT** have a `DeviceName` column. You **MUST** join with `DeviceInfo` to resolve device names. Using `DeviceName` directly will fail with `SemanticError: Failed to resolve scalar expression named 'DeviceName'`. The query below already includes the required join. If the table returns empty or error, skip gracefully — it requires Defender Vulnerability Management add-on licensing.

```kql
DeviceTvmCertificateInfo
| extend Status = case(
    ExpirationDate < now(), "Expired",
    ExpirationDate < datetime_add('day', 30, now()), "Expiring within 30 days",
    "Valid"
)
| where Status != "Valid"
| summarize CertCount = count() by Status, DeviceId
| join kind=inner (
    DeviceInfo | summarize arg_max(Timestamp, DeviceName) by DeviceId
) on DeviceId
| project DeviceName, Status, CertCount
| order by Status asc, CertCount desc
```

**Purpose:** Identify expired and soon-expiring certificates that can cause service outages or security gaps.

> **Note:** `DeviceTvmCertificateInfo` does NOT have a `DeviceName` column — you must join with `DeviceInfo` to resolve device names. If the table returns empty or error, skip gracefully — it requires Defender Vulnerability Management add-on licensing.

---

### Query 14: Top Vulnerable Software

```kql
DeviceTvmSoftwareVulnerabilities
| summarize 
    CriticalCVEs = countif(VulnerabilitySeverityLevel == "Critical"),
    HighCVEs = countif(VulnerabilitySeverityLevel == "High"),
    TotalCVEs = count(),
    AffectedDevices = dcount(DeviceId)
    by SoftwareVendor, SoftwareName
| order by CriticalCVEs desc, HighCVEs desc, TotalCVEs desc
| take 15
```

**Purpose:** Identify which software products contribute the most vulnerabilities — useful for upgrade/removal decisions.

---

### Query 15: Internet-Facing Critical Assets with Vulnerabilities

```kql
ExposureGraphNodes
| where set_has_element(Categories, "device")
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| extend critLevel = rawData.criticalityLevel
| where isnotnull(critLevel) and toint(critLevel.criticalityLevel) < 4
| where isnotnull(rawData.IsInternetFacing)
| extend VulnerableToRCE = isnotnull(rawData.vulnerableToRCE)
| extend VulnerableToPrivEsc = isnotnull(rawData.VulnerableToPrivilegeEscalation)
| project 
    DeviceName = NodeName,
    CriticalityLevel = toint(critLevel.criticalityLevel),
    VulnerableToRCE,
    VulnerableToPrivEsc,
    NodeLabel
| order by CriticalityLevel asc
```

**Purpose:** Highest-risk combination: critical + internet-facing + vulnerable. Always Priority 1 remediation.

---

### Query 16: Multi-Hop Attack Path Enumeration

> **⚠️ Optional — slow query.** Only run when Q10a/Q10b reveal high exposure (e.g., many vulnerable devices with identity edges) and the user explicitly requests attack path enumeration. Skip by default in standard reports.

```kql
let IdentitiesAndCriticalDevices = ExposureGraphNodes
| extend rawData = parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))
| extend HasRCEVuln = isnotnull(rawData.vulnerableToRCE)
| extend CritLevel = toint(rawData.criticalityLevel.criticalityLevel)
| extend HasCritLevel = isnotnull(rawData.criticalityLevel)
| where 
    (set_has_element(Categories, "device") and 
        (
            (HasCritLevel and CritLevel < 4)
            or 
            HasRCEVuln
        )
    )
    or 
    set_has_element(Categories, "identity");
ExposureGraphEdges
| where EdgeLabel in~ ("can authenticate as", "CanRemoteInteractiveLogonTo")
| make-graph SourceNodeId --> TargetNodeId with IdentitiesAndCriticalDevices on NodeId
| graph-match (DeviceWithRCE)-[CanConnectAs]->(Identity)-[CanRemoteLogin]->(CriticalDevice)
    where 
        CanConnectAs.EdgeLabel =~ "can authenticate as" and
        CanRemoteLogin.EdgeLabel =~ "CanRemoteInteractiveLogonTo" and
        set_has_element(Identity.Categories, "identity") and 
        set_has_element(DeviceWithRCE.Categories, "device") and DeviceWithRCE.HasRCEVuln and
        set_has_element(CriticalDevice.Categories, "device") and CriticalDevice.HasCritLevel
    project 
        RCEDeviceName = DeviceWithRCE.NodeName,
        IdentityName = Identity.NodeName,
        CriticalDeviceName = CriticalDevice.NodeName,
        CriticalityLevel = tostring(CriticalDevice.CritLevel)
| order by CriticalityLevel asc
```

**Purpose:** Discover multi-hop attack chains: RCE-vulnerable device → user identity → critical server. This is the heavy `graph-match` query — use Q10a/Q10b for fast summary stats, and only run this when deep enumeration is needed.

> **Note:** This query may return 0 results if no RCE→identity→critical-device paths exist. That's a positive finding — report as "✅ No multi-hop attack paths from RCE-vulnerable devices to critical servers detected."

> **Performance:** ⚠️ Slow — uses `make-graph` + `graph-match`. Can take 30-60+ seconds on large environments. Filter nodes tightly BEFORE `make-graph` to reduce graph size.

> **Additional patterns:** See `queries/cloud/exposure_graph_attack_paths.md` for 30+ query patterns covering cookie chains, permission analysis, choke point detection, and Azure Resource Graph integration.

---

## Risk Assessment

Compute an overall risk rating based on query results:

| Rating | Criteria |
|--------|----------|
| 🔴 **Critical** | Any: exploitable Critical CVEs on internet-facing assets, OR compliance rate < 40%, OR internet-facing devices with high/critical vulnerabilities (Q10a), OR high blast radius from vulnerable devices to identities/data stores (Q10b) |
| 🟠 **High** | Any: exploitable High CVEs > 5, OR EoS software on critical assets, OR compliance rate < 60%, OR active devices with RTP/TamperProtection/AVMode non-compliant |
| 🟡 **Medium** | Any: total High CVEs > 50, OR EoS software present, OR compliance rate < 75%, OR expired certificates > 10 |
| 🟢 **Low** | None of the above criteria met |

**Cite specific evidence** when assigning risk level (per copilot-instructions.md Evidence-Based Analysis rule).

---

## Report Template

### Inline Chat Executive Summary

```markdown
📊 VULNERABILITY & EXPOSURE REPORT — <DATE>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Overall Risk:** 🔴 / 🟠 / 🟡 / 🟢 <RATING> — <1-sentence justification with evidence>

### Vulnerability Overview
| Severity | CVE Count | Devices Affected |
|----------|-----------|------------------|
| 🔴 Critical | X | Y |
| 🟠 High | X | Y |
| 🟡 Medium | X | Y |
| 🔵 Low | X | Y |

⚠️ **X CVEs with known exploits** — see full report for details

### Configuration Compliance
| Category | Compliant % | Non-Compliant |
|----------|-------------|---------------|
| OS | X% | Y |
| Network | X% | Y |
| Security Controls | X% | Y |
| Accounts | X% | Y |
| Application | X% | Y |

### Attack Path Exposure
| Metric | Count |
|--------|-------|
| Devices with high/critical vulnerabilities | X of Y |
| Internet-facing vulnerable devices | Z |
| Critical assets with vulnerabilities | N |
| Lateral movement paths (identity edges) | X → Y targets |
| Data access paths (permission edges) | X → Y targets |

🔗 **Full interactive attack paths:** [Exposure Management Portal](https://security.microsoft.com/exposure-management/attack-paths)

### Defender Device Health
**Active Devices:** X/Y controls fully compliant across Z active devices
**Inactive Devices:** N devices not reporting (excluded — stale signatures expected)
⚠️ / ✅ **Non-compliant active devices:** <count and failed control names, or "None">

### Key Findings
- 🔴 <Critical finding 1>
- 🟠 <High finding 2>
- ⚠️ <Notable finding 3>
- ✅ <Positive finding>

### 🎯 TOP 3 PRIORITY ACTIONS
1. 🔴 <Action 1 — e.g., Patch X exploitable CVEs on internet-facing assets>
2. 🟠 <Action 2 — e.g., Remediate Y Impact-9 security misconfigurations>
3. ⚠️ <Action 3 — e.g., Upgrade Z end-of-support software>

📄 Full report: reports/exposure/vulnerability_exposure_report_<YYYYMMDD_HHMMSS>.md
```

### Markdown File Structure

The full markdown report file MUST follow this structure:

```markdown
# Vulnerability & Exposure Management Report

**Generated:** <DATE>
**Scope:** <Org-Wide / Device: HOSTNAME>
**Overall Risk Rating:** 🔴/🟠/🟡/🟢 <RATING>

---

## 1. Executive Summary
- Overall risk rating with evidence
- Key metrics dashboard
- Top 3 priority remediation actions

## 2. CVE Vulnerability Assessment

🔗 **Browse all CVEs in Defender portal:** [Weaknesses](https://security.microsoft.com/vulnerabilities) | [Software Inventory](https://security.microsoft.com/software-inventory)

### 2a. Severity Distribution
<Table: Severity × CVE Count × Device Count>

### 2b. Exploitable Vulnerabilities
<Table: CVE ID, CVSS, Description, Affected Devices — sorted by CVSS desc>

### 2c. Top Vulnerable Software
<Table: Vendor, Software, Critical/High/Total CVEs, Affected Devices>

### 2d. Per-Device Vulnerability Matrix
<Table: Device, OS, Critical/High/Med/Low/Total>

## 3. Security Configuration Compliance

🔗 **Detailed recommendations in Defender portal:** [Security Recommendations](https://security.microsoft.com/exposure-recommendations) | [Vulnerability Management Dashboard](https://security.microsoft.com/vulnerability-management/dashboard)

### 3a. Compliance by Category
<Table: Category, Total, Compliant %, Non-Compliant>

### 3b. Per-Device Compliance Scorecard
<Table: Device, Compliance %, Compliant/NonCompliant/NA counts>

### 3c. High-Impact Misconfigurations (Impact ≥ 8)
For each misconfiguration:
- **Configuration:** <Name>
- **Category:** <Category> > <Subcategory>
- **Impact Score:** <Score>/10
- **Risk:** <RiskDescription>
- **Affected Devices:** <count> (<device list>)
- **Remediation:** <Summary of RemediationOptions — strip HTML tags>

## 4. End-of-Support Software
<Table: Vendor, Software, Version, EoS Status, EoS Date, Affected Devices>

## 5. Exposure Management

### 5a. Critical Asset Inventory
<Table: Device, Criticality Level, Internet-Facing, RCE Vuln, PrivEsc Vuln>

### 5b. Attack Path & Exposure Analysis

**Vulnerable Device Exposure (Q10a):**
| Metric | Count |
|--------|-------|
| Total devices | X |
| Devices with high/critical vulnerabilities | Y |
| Internet-facing vulnerable devices | Z |
| RCE-vulnerable devices | N |
| Critical assets with vulnerabilities | N |

**Blast Radius from Vulnerable Devices — 1-Hop Connectivity (Q10b):**
| Edge Type | Target Type | Path Count | Unique Targets | Sample Targets |
|-----------|-------------|------------|----------------|----------------|
| can authenticate as | Identity | X | Y | ... |
| has permissions to | Data Store | X | Y | ... |
| ... | ... | ... | ... | ... |

**Interpretation:** <Narrative summarizing lateral movement risk, data access risk, and key choke points>

🔗 **Full interactive attack path analysis:** [Exposure Management Portal](https://security.microsoft.com/exposure-management/attack-paths)

> If Q16 was run (optional deep-dive):
> **Multi-Hop Attack Chains (Q16):** <Table: Entry Device → Identity → Target Device / Criticality>
> Or: "✅ No multi-hop attack paths from RCE-vulnerable devices to critical servers detected."

## 6. Endpoint Health

### 6a. Defender Device Health
**Fleet Summary (Active Devices):** <Table: Control × OS Platform × Compliant / NonCompliant / ComplianceRate — active devices only>
**Inactive Device Summary:** <Count of inactive devices by OS — signature staleness is expected, flag for decommissioning review>
**Non-Compliant Exceptions (Active Only):** <Table: Device, OS, Failed Controls, Count — only active devices failing Defender controls>
If no non-compliant active devices: "✅ All active devices pass all Defender health controls"
If non-compliant only on inactive: "⚠️ X inactive devices have stale Defender configurations — verify if devices should be decommissioned or reconnected"

### 6b. Certificate Status
<Table: Device, Expired/Expiring count>

## 7. Prioritized Remediation Plan

🔗 **Track remediation in Defender portal:** [Remediation Activities](https://security.microsoft.com/vulnerability-management/remediation) | [Security Recommendations](https://security.microsoft.com/exposure-recommendations)

| Priority | Category | Action | Impact |
|----------|----------|--------|--------|
| 🔴 Immediate | ... | ... | ... |
| 🟠 Short-term | ... | ... | ... |
| 🟡 Medium-term | ... | ... | ... |
| 🟢 Ongoing | ... | ... | ... |

## 8. Appendix
- Query reference (all KQL queries used)
- Data freshness notes
- Methodology
```

---

## Per-Device Mode

When user specifies a device name, scope all DeviceTvm queries to that device:

**Add filter to Queries 1-6, 8, 9, 11, 13, 14:**
```kql
| where DeviceName =~ '<DEVICE_NAME>'
```

**ExposureGraph queries (7, 15):** Filter by `NodeName`:
```kql
| where NodeName =~ '<DEVICE_NAME>'
```

**Per-device report differences:**
- Section 5b (Attack paths) — filter to paths involving the specific device
- Title changes to: `Vulnerability & Exposure Report — <DEVICE_NAME>`

---

## Known Pitfalls

| Pitfall | Impact | Mitigation |
|---------|--------|------------|
| `DeviceTvmCertificateInfo` requires Defender VM add-on | Query returns empty or error | Skip gracefully, note in report: "Certificate data requires Defender Vulnerability Management add-on" |
| `DeviceTvmBrowserExtensions` may be empty | No browser extension data | Skip section, note as "No browser extension data available" |

| `RemediationOptions` in KB tables contains HTML | Raw HTML in output | Strip HTML tags when rendering in markdown: remove `<br/>`, `<ol>`, `<li>`, `<a>` tags, convert to plain text bullet points |
| `NodeProperties` is a JSON string, NOT a parsed dynamic object | Direct dot-notation like `NodeProperties.rawData.criticalityLevel` returns null through MCP JSON serialization — queries silently return 0 results | **MUST** use double `parse_json(tostring())` extraction: `parse_json(tostring(parse_json(tostring(NodeProperties)).rawData))` then access sub-properties. This is the ONLY reliable pattern for `NodeProperties` access. See Q7, Q10a, Q10b, Q15, Q16 for canonical examples |
| `ConfigurationBenchmarks` in KB contains benchmark mappings | Can enrich report | Optional: extract CIS/NIST benchmark references for compliance mapping |
| DeviceTvm assessments refresh periodically | Data may be 12-24h old | Note data freshness in report appendix |
| `graph-match` queries can be slow on large graphs | Timeout possible | Filter nodes BEFORE `make-graph` to reduce graph size |
| `parse_json()` and `graph-match project` produce dynamic-typed columns | `order by` fails with "key can't be of dynamic type" error | Always wrap in explicit type casts (`toint()`, `tostring()`, `tolong()`) before using in `order by`, `summarize`, or comparisons. Applies to ALL `parse_json()` output — not just `graph-match`. Example: `| extend critValue = toint(rawData.criticalityLevel.criticalityLevel)` then `| order by critValue asc` |
| `DeviceTvmInfoGathering` table exists but is NOT used by this skill | Agent may attempt to query it for Defender health data, causing errors due to unfamiliar schema | Defender sensor health is covered by Q9 (SCIDs in `DeviceTvmSecureConfigurationAssessment`). Do NOT improvise queries against `DeviceTvmInfoGathering` — its schema differs from other DeviceTvm* tables and is not documented here |
| `DeviceTvmCertificateInfo` has NO `DeviceName` column | `Failed to resolve scalar expression named 'DeviceName'` | Join with `DeviceInfo \| summarize arg_max(Timestamp, DeviceName) by DeviceId` to resolve device names |
| `Context` in `DeviceTvmSecureConfigurationAssessment` is double-nested JSON | First `parse_json(Context)` returns an array of JSON strings; items need a second `parse_json()` to extract values | Use `parse_json(tostring(parse_json(Context)[0]))[N]` — e.g., `[0]` for AV mode code, `[2]` for signature date |
| SCID numbers are OS-specific — same control has different IDs per platform | Querying Windows SCIDs on macOS/Linux returns `IsApplicable=0` | Use the SCID mapping: Windows `2010-2030`, macOS `5090-5095`, Linux `6090-6095`. Q9/Q11 normalize OS-specific SCIDs to unified control names |
| Inactive devices have naturally stale AV signatures | Non-compliant `AVSignatures` on devices offline >7 days is expected, not a security gap | Always join `DeviceInfo` to separate active (seen <7d) from inactive devices; report inactive signature staleness as informational only |

---

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| `SemanticError: Failed to resolve table 'DeviceTvm...'` | Table not available in AH | Verify Defender for Endpoint is onboarded; some DeviceTvm* tables require premium licensing |
| `SemanticError: Failed to resolve table 'ExposureGraphNodes'` | Exposure Management not enabled | Report as: "⚠️ Microsoft Security Exposure Management is not enabled in this tenant. ExposureGraph sections skipped." |
| Query timeout on graph-match | Graph too large | Reduce node set with tighter filters; try simpler edge queries first |
| Empty results from DeviceTvmSoftwareVulnerabilities | No onboarded devices or no vulns detected | Verify at least one device is MDE-onboarded: `DeviceInfo | summarize by DeviceName | take 5` |
| `DeviceTvmCertificateInfo` not found | Requires Defender Vulnerability Management add-on | Skip section, note in report |

### Graceful Degradation

If a table or query fails, **do not abort the entire report**. Skip the affected section and note it:

```markdown
### 6b. Certificate Status
❓ Certificate data not available — `DeviceTvmCertificateInfo` table not found.
This may require the Defender Vulnerability Management add-on license.
```

Continue with all remaining sections. The report should always produce output for at least:
- CVE Vulnerability Assessment (Sections 2a-2d)
- Security Configuration Compliance (Sections 3a-3c)

These are available in all Defender for Endpoint tenants.

---

## Additional References

- [Query the Enterprise Exposure Graph](https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph)
- [DeviceTvmSoftwareVulnerabilities schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table)
- [DeviceTvmSecureConfigurationAssessment schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table)
- [Microsoft Security Exposure Management overview](https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management)
- Existing query library: `queries/cloud/exposure_graph_attack_paths.md`
