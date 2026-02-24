---
name: detection-authoring
description: "Create, deploy, update, and manage custom detection rules in Microsoft Defender XDR via the Graph API (/beta/security/rules/detectionRules). Covers query adaptation from Sentinel KQL to custom detection format, deployment via PowerShell (Invoke-MgGraphRequest), manifest-driven batch deployment, and lifecycle management (list, enable/disable, delete). Companion script: Deploy-CustomDetections.ps1."
---

# Custom Detection Authoring — Instructions

## Purpose

This skill deploys **custom detection rules** to Microsoft Defender XDR via the Microsoft Graph API (`/beta/security/rules/detectionRules`). It handles:

- **Query adaptation** — Converting Sentinel KQL queries into custom detection format
- **Single-rule deployment** — Creating one rule via Graph API
- **Batch deployment** — Deploying multiple rules from a JSON manifest
- **Lifecycle management** — Listing, updating, enabling/disabling, and deleting rules
- **Validation** — Dry-run queries in Advanced Hunting before deployment

**Entity Type:** Custom detection rules (Defender XDR)

---

## 📑 TABLE OF CONTENTS

1. **[Prerequisites](#prerequisites)** — Auth, scopes, PowerShell modules
2. **[Critical Rules](#-critical-rules---read-first-)** — Mandatory constraints
3. **[Query Adaptation](#query-adaptation)** — Sentinel KQL → Custom Detection format
4. **[API Reference](#api-reference)** — Graph API schema and field values
5. **[Frequency & Lookback](#frequency--lookback)** — Schedule periods, lookback windows, NRT constraints
6. **[Deployment Workflow](#deployment-workflow)** — Step-by-step process
7. **[Batch Deployment](#batch-deployment)** — Manifest-driven multi-rule deployment
8. **[Lifecycle Management](#lifecycle-management)** — CRUD operations
9. **[Known Pitfalls](#known-pitfalls)** — Lessons learned
10. **[CD Metadata Contract](#cd-metadata-contract)** — Schema for query file ↔ detection skill coordination
11. **[Query Library Reference](#query-library-reference)** — Deployable query catalog

---

## Prerequisites

### Required PowerShell Module

```powershell
# Microsoft.Graph.Authentication — provides Invoke-MgGraphRequest
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Required Graph API Scopes

| Operation | Scope | Type |
|-----------|-------|------|
| List / Get rules | `CustomDetection.Read.All` | Delegated |
| Create / Update / Delete | `CustomDetection.ReadWrite.All` | Delegated |

### Authentication

```powershell
# Read-only
Connect-MgGraph -Scopes "CustomDetection.Read.All" -NoWelcome

# Full CRUD
Connect-MgGraph -Scopes "CustomDetection.ReadWrite.All" -NoWelcome
```

> **Why `Invoke-MgGraphRequest`?** The Graph MCP server and `az rest` both return 403 for custom detection endpoints — they lack the `CustomDetection.*` scopes. `Invoke-MgGraphRequest` uses interactive delegated auth with consent, which works.

### Companion Script

[Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) — PowerShell script for manifest-driven batch deployment. See [Batch Deployment](#batch-deployment).

---

## ⚠️ CRITICAL RULES — READ FIRST ⚠️

### Mandatory Query Requirements

Custom detection queries have strict requirements that differ from Sentinel analytic rules:

| Requirement | Detail |
|-------------|--------|
| **Timestamp column must be projected as-is** | The query MUST project the timestamp column **exactly as it appears in the source table** — `TimeGenerated` for Sentinel/LA tables, `Timestamp` for XDR-native tables. Do not alias one to the other (e.g., `Timestamp = TimeGenerated` causes `400 Bad Request`). See [Pitfall 1](#pitfall-1-timestamp-vs-timegenerated). |
| **Row-level results with required columns** | Query output must include the timestamp column (`TimeGenerated` or `Timestamp` per source table), `DeviceName`, and `ReportId`. A bare `summarize count()` or `make_set()` fails because these columns are lost. However, `summarize` with `arg_max` IS allowed — see [Pitfall 3](#pitfall-3-summarize--allowed-only-with-row-level-output). |
| **`ReportId` column required** | Must project a `ReportId` column. For tables without a native `ReportId`, use a proxy (e.g., `CallerProcessId`). |
| **`DeviceName` column required** | Must project a `DeviceName` column. Alias from `Computer` if needed. |
| **No `let` statements (NRT)** | **NRT rules (`schedule: "0"`) reject `let` entirely** — the API returns a generic `400 Bad Request`. This is **not documented by Microsoft** (empirically discovered Feb 2026) but consistently reproducible. Inline all dynamic arrays/lists directly in `where` clauses. Non-NRT rules (1H+) tolerate `let`. |
| **150 alerts per run** | Each rule generates a maximum of 150 alerts per execution. Tune the query to avoid alerting on normal day-to-day activity. |
| **First run = 30-day backfill** | When a new rule is saved, it immediately runs against the past 30 days of data. Expect a burst of initial alerts if the query has broad coverage. |

### Query Adaptation Checklist

When converting a Sentinel query to custom detection format:

1. ✅ Remove bare `summarize` — project raw rows instead. Exception: `summarize` with `arg_max` is allowed for threshold-based detections (see [Pitfall 3](#pitfall-3-summarize--allowed-only-with-row-level-output))
2. ✅ Project the timestamp column as-is: `TimeGenerated = TimeGenerated` for Sentinel/LA tables, `Timestamp` for XDR tables. Never alias one to the other.
3. ✅ Alias `Computer` → `DeviceName` (or use `DeviceId` if available)
4. ✅ Add `ReportId` — use native `ReportId` if available, otherwise proxy (e.g., `CallerProcessId`). **Caveat:** proxy columns may contain empty strings for some events — this is acceptable but means those rows won't be individually identifiable in alert details
5. ✅ Add a time filter as the first `where` clause — prefer `ingestion_time() > ago(1h)` over `TimeGenerated > ago(1h)` (see tip below). **NRT exception:** For NRT rules (`schedule: "0"`), omit the time filter entirely — events are processed as they stream in, and the platform pre-filters automatically.
6. ✅ Remove `let` variables for NRT rules — **NRT rejects `let` entirely** (generic 400 error, undocumented). Inline all dynamic arrays directly in `where` clauses. Non-NRT rules tolerate `let`.
7. ✅ Validate via Advanced Hunting dry-run before deployment

> **Performance tip (from MS Learn):** "Avoid filtering custom detections by using the `Timestamp` column. The data used for custom detections is prefiltered based on the detection frequency." Use `ingestion_time()` instead — it aligns with the platform's pre-filtering for better performance. For scheduled rules, match the time filter to the run frequency (`ingestion_time() > ago(1h)` for 1H rules). For NRT rules, no time filter is needed.

### Example Adaptation

**Before (Sentinel KQL — uses summarize):**
```kql
let _Lookback = 7d;
SecurityEvent
| where TimeGenerated > ago(_Lookback)
| where EventID == 4799
| where TargetSid == "S-1-5-32-544"
| where SubjectUserSid != "S-1-5-18"
| where AccountType != "Machine"
| where not(SubjectUserSid endswith "-500")
| project TimeGenerated, Computer, Actor = SubjectUserName, ...
| summarize EnumerationCount = count(), Processes = make_set(CallerProcess)
    by Actor, ActorDomain, ActorSID
```

**After (Custom Detection — row-level, mandatory columns):**
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4799
| where TargetSid == "S-1-5-32-544"
| where SubjectUserSid != "S-1-5-18"
| where AccountType != "Machine"
| where not(SubjectUserSid endswith "-500")
| project
    TimeGenerated = TimeGenerated,
    DeviceName = Computer,
    AccountName = SubjectUserName,
    AccountDomain = SubjectDomainName,
    AccountSid = SubjectUserSid,
    CallerProcess = CallerProcessName,
    ReportId = CallerProcessId
```

**Key changes:**
- Removed `let _Lookback` → hardcoded `ago(1h)`
- Removed `summarize` → raw `project`
- Added `TimeGenerated = TimeGenerated` (identity projection — mandatory)
- Added `DeviceName = Computer` (mandatory column)
- Added `ReportId = CallerProcessId` (proxy ReportId)

---

## API Reference

### Endpoint

```
POST   /beta/security/rules/detectionRules          — Create
GET    /beta/security/rules/detectionRules           — List all
GET    /beta/security/rules/detectionRules/{id}      — Get by ID
PATCH  /beta/security/rules/detectionRules/{id}      — Update
DELETE /beta/security/rules/detectionRules/{id}      — Delete
```

### Schedule Periods

| Value | Meaning | Notes |
|-------|---------|-------|
| `"0"` | NRT (Near Real-Time / Continuous) | Runs continuously. See [NRT Constraints](#nrt-constraints). |
| `"1H"` | Every 1 hour | Most common for custom detections |
| `"3H"` | Every 3 hours | |
| `"12H"` | Every 12 hours | |
| `"24H"` | Every 24 hours | Daily |

### Alert Severity Values

| Value | Use Case |
|-------|----------|
| `"informational"` | Baseline queries, low-noise canaries |
| `"low"` | Suspicious but may be benign |
| `"medium"` | Likely malicious, needs investigation |
| `"high"` | High-confidence detection, immediate response |

### Alert Category Values

Valid MITRE ATT&CK tactic names (title case):

`InitialAccess`, `Execution`, `Persistence`, `PrivilegeEscalation`, `DefenseEvasion`, `CredentialAccess`, `Discovery`, `LateralMovement`, `Collection`, `Exfiltration`, `CommandAndControl`, `Impact`, `Reconnaissance`, `ResourceDevelopment`

### Impacted Asset Types

**Device asset:**
```json
{
    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
    "identifier": "<identifier>"
}
```

Valid device identifiers: `deviceId`, `deviceName`, `remoteDeviceName`, `targetDeviceName`, `destinationDeviceName`

**User asset:**
```json
{
    "@odata.type": "#microsoft.graph.security.impactedUserAsset",
    "identifier": "<identifier>"
}
```

Valid user identifiers: `accountObjectId`, `accountSid`, `accountUpn`, `accountName`, `accountDomain`, `accountId`, `requestAccountSid`, `requestAccountName`, `requestAccountDomain`, `recipientObjectId`, `processAccountObjectId`, `initiatingAccountSid`, `initiatingProcessAccountUpn`, `initiatingAccountName`, `initiatingAccountDomain`, `servicePrincipalId`, `servicePrincipalName`, `targetAccountUpn`

**Mailbox asset:**
```json
{
    "@odata.type": "#microsoft.graph.security.impactedMailboxAsset",
    "identifier": "<identifier>"
}
```

Valid mailbox identifiers: `recipientEmailAddress`, `senderEmailAddress`, `senderObjectId`

### Minimal Valid POST Body

```json
{
    "displayName": "Rule Name",
    "isEnabled": true,
    "queryCondition": {
        "queryText": "SecurityEvent\r\n| where TimeGenerated > ago(1h)\r\n| ..."
    },
    "schedule": {
        "period": "1H"
    },
    "detectionAction": {
        "alertTemplate": {
            "title": "Alert Title",
            "description": "Alert description text.",
            "severity": "medium",
            "category": "Discovery",
            "recommendedActions": null,
            "mitreTechniques": ["T1069.001"],
            "impactedAssets": [
                {
                    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                    "identifier": "deviceName"
                }
            ]
        },
        "responseActions": []
    }
}
```

> **`recommendedActions`**: Can be `null` or a string. The portal sets it to `null` by default.

> **`responseActions`**: Array of automated response actions. Empty `[]` for alert-only rules. **Must be `[]`, not `null`** — sending `null` causes `400 Bad Request`. See [Pitfall 9](#pitfall-9-powershell-empty-array-swallowing--organizationalscope).

> **`organizationalScope`**: Omit this field entirely for tenant-wide rules (the API default). Including `"organizationalScope": null` explicitly may cause `400 Bad Request` in some API versions.

### Dynamic Alert Titles and Descriptions

Alert titles and descriptions can reference query result columns using `{{ColumnName}}` syntax, making alerts self-descriptive:

```json
{
    "title": "Admin Group Enumeration by {{AccountName}} on {{DeviceName}}",
    "description": "User {{AccountName}} enumerated group {{TargetGroupName}} on the device."
}
```

| Constraint | Limit |
|------------|-------|
| Max unique dynamic columns | **3 unique `{{Column}}` references TOTAL across `title` AND `description` combined** — NOT per field.  E.g., the example above uses `AccountName` + `DeviceName` in title and `AccountName` + `TargetGroupName` in description = 3 unique columns (AccountName is reused). Exceeding this returns `400 Bad Request` with "Dynamic properties in alertTitle and alertDescription must not exceed 3 fields". |
| | **⚠️ Discrepancy with MS Learn docs:** The [official documentation](https://learn.microsoft.com/defender-xdr/custom-detection-rules) states "The number of columns you can reference in each field is limited to three" (i.e., 3 per field). However, the Graph API empirically enforces **3 unique columns total** across both fields combined (confirmed Feb 2026). The portal UI may enforce the per-field limit differently than the API. Use 3 unique total as the safe limit for Graph API deployments. |
| Format | `{{ExactColumnName}}` — must match a column in query output |
| Markup | Plain text only — HTML, Markdown, and code are sanitized |
| URLs | Must use percent-encoding format |

---

## Frequency & Lookback

### Lookback Windows by Frequency

Each frequency has a built-in lookback window. Results outside this window are ignored even if the query requests them:

| Frequency | Lookback Period | Query Filter Recommendation |
|-----------|----------------|-----------------------------|
| NRT (Continuous) | Streaming | No time filter needed — events processed as collected |
| Every 1 hour | Past **4 hours** | `ago(4h)` or `ago(1h)` |
| Every 3 hours | Past **12 hours** | `ago(12h)` or `ago(3h)` |
| Every 12 hours | Past **48 hours** | `ago(48h)` or `ago(12h)` |
| Every 24 hours | Past **30 days** | `ago(30d)` or `ago(24h)` |
| Custom (Sentinel only) | 4× frequency (<daily) or 30d (≥daily) | Match lookback |

> **Tip:** Match the query time filter to the run frequency (`ago(1h)` for 1H rules), not the full lookback window. The lookback ensures late-arriving data is caught, but your filter should target the detection window.

### NRT Constraints

NRT (Continuous, `period: "0"`) rules have stricter requirements than scheduled rules:

| Constraint | Detail |
|------------|--------|
| **Single table only** | Query must reference exactly one table — no joins or unions |
| **No `let` statements** | `let` variables are silently rejected — the API returns a generic `400 Bad Request` with no useful error message. **Always inline dynamic arrays/lists directly in `where` clauses.** This constraint is **not listed in the [official NRT docs](https://learn.microsoft.com/defender-xdr/custom-detection-rules#queries-you-can-run-continuously)** (which list only 4 constraints) but is consistently reproducible via Graph API (empirically confirmed Feb 2026). |
| **No `externaldata`** | Cannot use the `externaldata` operator |
| **No comments** | Query text must not contain any comment lines (`//`) |
| **Supported operators only** | Limited to [supported KQL features](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations-structure#supported-kql-features) |
| **No time filter needed** | NRT processes events as they stream in. The platform pre-filters automatically. Adding a time filter (e.g., `TimeGenerated > ago(1h)`) is unnecessary but harmless. |

### NRT-Supported Tables

Not all tables support NRT frequency. Use NRT only with these tables:

**Defender XDR tables:**
`AlertEvidence`, `CloudAppEvents`, `DeviceEvents`, `DeviceFileCertificateInfo`, `DeviceFileEvents`, `DeviceImageLoadEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`, `DeviceNetworkInfo`, `DeviceInfo`, `DeviceProcessEvents`, `DeviceRegistryEvents`, `EmailAttachmentInfo`, `EmailEvents`\*, `EmailPostDeliveryEvents`, `EmailUrlInfo`, `IdentityDirectoryEvents`, `IdentityLogonEvents`, `IdentityQueryEvents`, `UrlClickEvents`

\* `EmailEvents`: `LatestDeliveryLocation` and `LatestDeliveryAction` columns are excluded from NRT.

**Sentinel tables (Preview):**
`ABAPAuditLog_CL`, `AuditLogs`, `AWSCloudTrail`, `AWSGuardDuty`, `AzureActivity`, `Cisco_Umbrella_dns_CL`, `Cisco_Umbrella_proxy_CL`, `CommonSecurityLog`, `GCPAuditLogs`, `MicrosoftGraphActivityLogs`, `OfficeActivity`, `Okta_CL`, `OktaV2_CL`, `ProofpointPOD`, `ProofPointTAPClicksPermitted_CL`, `ProofPointTAPMessagesDelivered_CL`, `SecurityAlert`, `SecurityEvent`, `SigninLogs`

> **Important:** `SecurityEvent` and `SigninLogs` support NRT — our Event ID 4799/4702 queries can run as NRT if they meet the single-table/no-joins constraint.

### Custom Frequency (Sentinel Data Only)

For rules based entirely on Sentinel-ingested data, a custom frequency is available (Preview):
- **Range:** 5 minutes to 14 days
- **Lookback:** Automatically calculated — 4× frequency for sub-daily, 30 days for daily or longer
- **Requirement:** Data must be available in Microsoft Sentinel (not XDR-only tables)

---

## Deployment Workflow

### Single Rule Deployment

**Step 1: Validate the query in Advanced Hunting**

Run the adapted query with a 1h lookback to validate schema:

```
Use RunAdvancedHuntingQuery with the adapted KQL query.
Confirm: 0 or more results, correct column schema (TimeGenerated, DeviceName, AccountName, etc.)
```

Then run with 30d lookback to confirm it returns real data:

```
Change ago(1h) to ago(30d) for the validation run.
Verify results contain expected columns and realistic data.
```

**Step 2: Check for duplicates, then build and POST the rule**

```powershell
Connect-MgGraph -Scopes "CustomDetection.ReadWrite.All" -NoWelcome

# Pre-flight: check if rule name already exists
$ruleName = "Rule Name"
$existing = (Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules" -OutputType PSObject).value `
    | Where-Object { $_.displayName -eq $ruleName }
if ($existing) {
    Write-Host "Rule '$ruleName' already exists (ID: $($existing.id)). Skipping POST."
    return
}

$body = @{
    displayName = $ruleName
    isEnabled = $true
    queryCondition = @{
        queryText = "SecurityEvent`r`n| where TimeGenerated > ago(1h)`r`n| ..."
    }
    schedule = @{ period = "1H" }
    detectionAction = @{
        alertTemplate = @{
            title = "Alert Title"
            description = "Description"
            severity = "medium"
            category = "Discovery"
            recommendedActions = $null
            mitreTechniques = @("T1069.001")
            impactedAssets = @(
                @{
                    "@odata.type" = "#microsoft.graph.security.impactedDeviceAsset"
                    identifier = "deviceName"
                }
            )
        }
        responseActions = @()
    }
} | ConvertTo-Json -Depth 10

$result = Invoke-MgGraphRequest -Method POST `
    -Uri "/beta/security/rules/detectionRules" `
    -Body $body -ContentType "application/json" -OutputType PSObject
```

**Step 3: Verify creation**

```powershell
$rules = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules" -OutputType PSObject
$rules.value | Select-Object id, displayName, isEnabled,
    @{N='Schedule';E={$_.schedule.period}},
    @{N='Status';E={$_.lastRunDetails.status}} | Format-Table -AutoSize
```

---

## Batch Deployment

Use the companion script [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) for manifest-driven batch deployment.

> **Manifest storage:** Save manifest JSON files in the `temp/` folder (gitignored). Manifests are deployment artifacts, not versioned query definitions.

### Manifest Format

See [example-manifest.json](example-manifest.json) for a complete 3-rule reference covering NRT, scheduled (with `summarize`/`arg_max`), and response action patterns.

The script reads a JSON file containing an array of rule definitions:

```json
[
    {
        "displayName": "Admin Group Enumeration by Non-Admin User",
        "title": "Admin Group Enumeration by {{AccountName}} on {{DeviceName}}",
        "queryText": "SecurityEvent\r\n| where TimeGenerated > ago(1h)\r\n| ...",
        "schedule": "0",
        "severity": "medium",
        "category": "Discovery",
        "mitreTechniques": ["T1069.001", "T1087.001"],
        "description": "User {{AccountName}} enumerated the local Administrators group.",
        "recommendedActions": "Verify whether the user has a legitimate reason to enumerate admin group membership.",
        "impactedAssets": [
            { "type": "device", "identifier": "deviceName" },
            { "type": "user", "identifier": "accountSid" }
        ],
        "responseActions": []
    }
]
```

### Usage

```powershell
# Dry-run — validate all queries in Advanced Hunting without creating rules
.\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json -DryRun

# Deploy all rules from manifest (skips existing rules by default)
.\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json

# Deploy and overwrite — attempt POST even if rule name exists (may cause 409)
.\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json -Force
```

---

## Lifecycle Management

### List All Rules

```powershell
$rules = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules" -OutputType PSObject
$rules.value | Select-Object id, displayName, isEnabled,
    @{N='Schedule';E={$_.schedule.period}},
    @{N='LastRun';E={$_.lastRunDetails.status}},
    @{N='Created';E={$_.createdDateTime}} | Format-Table -AutoSize
```

### Get Rule by ID

```powershell
$rule = Invoke-MgGraphRequest -Method GET `
    -Uri "/beta/security/rules/detectionRules/5632" -OutputType PSObject
$rule | ConvertTo-Json -Depth 10
```

### Update Rule (PATCH)

```powershell
$update = @{
    isEnabled = $false
    schedule = @{ period = "24H" }
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Method PATCH `
    -Uri "/beta/security/rules/detectionRules/5632" `
    -Body $update -ContentType "application/json"
```

### Delete Rule

```powershell
Invoke-MgGraphRequest -Method DELETE `
    -Uri "/beta/security/rules/detectionRules/5632"
```

> **⚠️ Deletion propagation delay:** After deleting a rule, the name remains reserved for ~30-60 seconds. Creating a rule with the same `displayName` during this window returns `409 Conflict` — but the rule may still be created despite the error. Always verify with a GET after creation.

### Enable/Disable Without Deleting

```powershell
# Disable
Invoke-MgGraphRequest -Method PATCH `
    -Uri "/beta/security/rules/detectionRules/5632" `
    -Body '{"isEnabled": false}' -ContentType "application/json"

# Enable
Invoke-MgGraphRequest -Method PATCH `
    -Uri "/beta/security/rules/detectionRules/5632" `
    -Body '{"isEnabled": true}' -ContentType "application/json"
```

---

## Known Pitfalls

### Pitfall 1: `Timestamp` vs `TimeGenerated` — Project As-Is

The query must project the timestamp column **exactly as it appears in the source table**. Do NOT alias one to the other.

| Source Table Type | Correct | Wrong |
|-------------------|---------|-------|
| Sentinel/LA tables (SecurityEvent, SigninLogs, AuditLogs, etc.) | `TimeGenerated = TimeGenerated` | `Timestamp = TimeGenerated` |
| XDR-native tables (DeviceEvents, DeviceProcessEvents, etc.) | `Timestamp` (native) | `TimeGenerated = Timestamp` |

The MS Learn docs confirm: "`Timestamp` or `TimeGenerated` — This column sets the timestamp for generated alerts. The query shouldn't manipulate this column and should return it exactly as it appears in the raw event." Aliasing across types causes `400 Bad Request`.

### Pitfall 2: Silent Rule Creation on Error Responses (400 AND 409)

**The API can silently create a rule even when it returns an error.** This applies to both `400 Bad Request` and `409 Conflict` responses.

**Cause A — 400 with partial validation:** A POST may pass structural validation (creating the rule) but fail a secondary check (e.g., `let` variable in NRT query, >3 dynamic fields). The API returns `400 Bad Request` — but the rule was already created. A subsequent retry with a fixed query then hits `409 Conflict` because the rule exists.

**Cause B — Deletion propagation delay:** Deleting a rule leaves a name reservation for ~30-60 seconds. POSTing a rule with the same `displayName` in this window returns `409 Conflict` — but the API may still create the rule.

**Cause C — Silent success + accidental retry:** When running `Invoke-MgGraphRequest` in a terminal, the POST may succeed but the output buffer splits across calls, making it look like nothing happened. Re-running the same POST produces a 409 because the rule was already created seconds earlier.

**Prevention:**
1. **Always run a GET before POST** to check if the rule name already exists (see [Step 2](#single-rule-deployment))
2. **Always verify with GET after ANY error response (400 or 409)** — the rule may have been created despite the error
3. **Never re-run a POST** without first checking via GET whether the previous attempt succeeded
4. **If a rule was silently created with a bad query**, use PATCH to update the `queryCondition.queryText` rather than deleting and re-creating

### Pitfall 3: `summarize` — Allowed Only With Row-Level Output

Custom detection queries must return row-level results with required columns (`TimeGenerated`, `DeviceName`, `ReportId`). A bare `summarize count()` or `make_set()` as the final operator fails validation because the output lacks these columns.

**However, `summarize` with `arg_max` IS allowed** when used to return the required columns alongside aggregation:

```kql
// ✅ ALLOWED — uses arg_max to preserve row-level columns
DeviceEvents
| where ingestion_time() > ago(1d)
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

This pattern counts by entity but still returns `Timestamp`, `ReportId`, and `DeviceId` per row — satisfying the requirement. Use this for threshold-based detections ("alert when count > N").

### Pitfall 4: Graph MCP and `az rest` Cannot Access This API

Both the Graph MCP server and `az rest` lack the `CustomDetection.ReadWrite.All` scope. Only `Invoke-MgGraphRequest` with interactive delegated auth works.

### Pitfall 5: `recommendedActions` Type

The `recommendedActions` field is a `String` (not an array). Set to `null` if not needed. The portal always sets it to `null`.

### Pitfall 6: Query Newlines

Use `\r\n` (CRLF) for line breaks in the `queryText` field. In PowerShell here-strings or backtick-escaped strings, use `` `r`n ``. The portal uses `\r\n` format.

### Pitfall 7: Duplicate Name Check

The API enforces unique `displayName` across all custom detections. Attempting to create a rule with an existing name returns `409 Conflict`. The batch deployment script checks for duplicates by default — use `-Force` to override.

### Pitfall 8: Alert Deduplication

Custom detections automatically deduplicate alerts. If a detection fires twice on events with the **same entities, custom details, and dynamic details**, only one alert is created. This can happen when the lookback period is longer than the run frequency (e.g., 1H frequency with 4H lookback means 3 hours of overlap). Different events on the same entity produce separate alert entries under the same alert.

---

## CD Metadata Contract

Query files in `queries/` can include per-query **cd-metadata blocks** that provide structured data for the detection authoring skill. This is the producer/consumer contract between the **KQL Query Authoring** skill (producer) and the **Detection Authoring** skill (consumer).

### When cd-metadata is present

When a query in `queries/` includes a cd-metadata block, the detection authoring skill uses it to:
- Pre-populate manifest fields (`schedule`, `severity`, `category`, `title`, `impactedAssets`, etc.)
- Skip manual CD-readiness assessment — the block declares readiness explicitly
- Generate the adapted CD query by applying the [Query Adaptation](#query-adaptation) checklist to the Sentinel query in the same section

### Schema

The cd-metadata block is an HTML comment with YAML content, placed immediately after the per-query metadata fields (`Severity`, `MITRE`, `Tuning Notes`) and before the KQL code block:

```markdown
### Query N: [Title]

**Purpose:** ...
**Severity:** High
**MITRE:** T1053.005, T1059.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Encoded PowerShell in Scheduled Task on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Investigate the scheduled task XML. Decode the base64 payload and check for malicious content."
adaptation_notes: "Straightforward — already row-level, add mandatory columns"
-->

```kql
// Query code...
```
```

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `cd_ready` | Yes | `true` / `false` | Whether this query can be adapted for custom detection deployment |
| `schedule` | If cd_ready | `"0"` / `"1H"` / `"3H"` / `"12H"` / `"24H"` | Detection frequency. `"0"` = NRT (single-table, no joins/unions) |
| `category` | If cd_ready | string | Alert category (see [API Reference](#api-reference) for valid values) |
| `title` | No | string | Dynamic alert title with `{{ColumnName}}` placeholders. Falls back to query heading if omitted |
| `impactedAssets` | If cd_ready | array | Asset entities to extract. Each entry: `type` (`device`/`user`/`mailbox`) + `identifier` (column name) |
| `recommendedActions` | No | string | Triage guidance shown in the alert. Omit if not needed |
| `responseActions` | No | array | Automated response actions (see [Response Actions Reference](#response-actions-reference)). Omit for alert-only |
| `adaptation_notes` | No | string | Human-readable notes on what adaptation is needed (for the summary table) |

### Queries NOT suitable for CD

For queries that cannot be adapted (baseline queries, statistical aggregations), use:

```markdown
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline query — requires summarize with dcount, not suitable for CD"
-->
```

This explicitly documents the assessment so the detection skill doesn't re-evaluate it each time.

### How the detection skill consumes cd-metadata

1. **User says "deploy query 8 as a custom detection"** → Skill reads the query file, finds the cd-metadata block for Query 8
2. **Pre-populates manifest entry** from cd-metadata fields (schedule, category, severity, title, impactedAssets)
3. **Applies [Query Adaptation](#query-adaptation) checklist** to the Sentinel KQL query in that section
4. **Deploys** via Graph API or generates manifest JSON for batch deployment

If a query file has **no cd-metadata blocks**, the skill falls back to the manual Query Library Reference table below.

---

## Response Actions Reference

Custom detections support automated response actions. Add to the `responseActions` array:

### Isolate Device

```json
{
    "@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction",
    "isolationType": "full",
    "identifier": "deviceId"
}
```

### Restrict App Execution

```json
{
    "@odata.type": "#microsoft.graph.security.restrictAppExecutionResponseAction",
    "identifier": "deviceId"
}
```

### Initiate Investigation

```json
{
    "@odata.type": "#microsoft.graph.security.initiateInvestigationResponseAction",
    "identifier": "deviceId"
}
```

### Collect Investigation Package

```json
{
    "@odata.type": "#microsoft.graph.security.collectInvestigationPackageResponseAction",
    "identifier": "deviceId"
}
```

### Run Antivirus Scan

```json
{
    "@odata.type": "#microsoft.graph.security.runAntivirusScanResponseAction",
    "identifier": "deviceId"
}
```

### Mark User as Compromised

Sets the user's risk level to "high" in Microsoft Entra ID, triggering Identity Protection policies:

```json
{
    "@odata.type": "#microsoft.graph.security.markUserAsCompromisedResponseAction",
    "identifier": "accountObjectId"
}
```

Valid identifiers: `accountObjectId`, `initiatingProcessAccountObjectId`, `recipientObjectId`

### Disable User

Temporarily prevents the user from signing in. Requires a SID-based identifier:

```json
{
    "@odata.type": "#microsoft.graph.security.disableUserResponseAction",
    "identifier": "accountSid"
}
```

Valid identifiers: `accountSid`, `initiatingProcessAccountSid`, `requestAccountSid`, `onPremSid`

### Force Password Reset

Prompts the user to change their password on next sign-in. Requires a SID-based identifier:

```json
{
    "@odata.type": "#microsoft.graph.security.forceUserPasswordResetResponseAction",
    "identifier": "accountSid"
}
```

### Allow/Block File

```json
{
    "@odata.type": "#microsoft.graph.security.blockFileResponseAction",
    "identifier": "sha1"
}
```

Valid identifiers: `sha1`, `initiatingProcessSHA1`, `sha256`, `initiatingProcessSHA256`

### Quarantine File

```json
{
    "@odata.type": "#microsoft.graph.security.quarantineFileResponseAction",
    "identifier": "sha1"
}
```

### Email Actions

Requires `networkMessageId` and `recipientEmailAddress` columns in query output:

```json
{
    "@odata.type": "#microsoft.graph.security.moveToDeletedItemsResponseAction",
    "identifier": "networkMessageId"
}
```

Other email action types: `moveToJunkResponseAction`, `moveToInboxResponseAction`, `softDeleteResponseAction`, `hardDeleteResponseAction`

> **⚠️ Use response actions with caution.** Automated isolation, user disablement, or app restriction can cause operational disruption. Start with alert-only rules (`responseActions: []`) and add automation after tuning.

---

## Additional Pitfalls (Discovered in Practice)

### Pitfall 9: PowerShell Empty Array Swallowing & `organizationalScope`

**Root cause (Feb 2026):** When using PowerShell `if/else` expressions to assign empty arrays, PowerShell swallows `@()` and produces `$null` instead:

```powershell
# ❌ BUG — $x becomes $null, NOT an empty array
$x = if ($false) { @($items) } else { @() }
# Result: $null

# ✅ CORRECT — assign first, then overwrite conditionally
$x = @()
if ($condition) { $x = @($items) }
# Result: empty Object[] (serializes to [])
```

This caused the batch deployment script to serialize `"responseActions": null` instead of `"responseActions": []`, which the API rejects with `400 Bad Request`.

**Combined with `organizationalScope: null`** — including this field explicitly (even as `null`) was also rejected. The fix: omit `organizationalScope` entirely and use direct assignment for `$respActions`.

**Symptoms:** All rules in a batch return `400 Bad Request`, but some may be silently created (see [Pitfall 2](#pitfall-2-silent-rule-creation-on-error-responses-400-and-409)). Manual deployment of the same rule body (without the null fields) succeeds.

**Fixed in:** [Deploy-CustomDetections.ps1](Deploy-CustomDetections.ps1) — `$respActions` now uses direct assignment, `organizationalScope` removed from body.
