---
name: geomap-visualization
description: Use this skill when asked to create geographic maps, visualize attack origins on a world map, show location-based data, or display IP geolocation. Triggers on keywords like "geomap", "world map", "geographic", "attack map", "show on map", "visualize locations", "attack origins", or when analyzing data with latitude/longitude coordinates.
---

# Geomap Visualization Skill

## Purpose

Generate interactive world map visualizations from Microsoft Sentinel data using the Sentinel Geomap MCP App. Geomaps display markers on a world map with coordinates, ideal for visualizing attack origins, geographic distribution of threats, or location-based security data.

---

## 📑 TABLE OF CONTENTS

1. **[Quick Start](#quick-start)** - Minimal example to get started
2. **[MCP Tool Reference](#mcp-tool-reference)** - Parameters and schemas
3. **[Data Sources](#data-sources)** - Tables with native vs enriched geolocation
4. **[KQL Query Patterns](#kql-query-patterns)** - Ready-to-use queries by scenario
5. **[Enrichment Integration](#enrichment-integration)** - Adding threat intel drill-down
6. **[Examples](#complete-examples)** - End-to-end workflows
7. **[Follow-Up Investigation Queries](#follow-up-investigation-queries)** - Queries for selected IPs
8. **[Interactive Selection Feature](#interactive-selection-feature)** - Multi-select and chat integration

---

## Quick Start

### Minimal Geomap (3 Steps)

```
# 1. Query Sentinel for data with coordinates
mcp_sentinel-data_query_lake({
  "query": "W3CIISLog | where TimeGenerated > ago(7d) | where scStatus == '401' | summarize value = count(), lat = take_any(RemoteIPLatitude), lon = take_any(RemoteIPLongitude) by ip = cIP | where lat != 0 | project ip, lat, lon, value"
})

# 2. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [<query results>],
  "title": "Attack Origins (Last 7 Days)",
  "valueLabel": "Failed Logins",
  "colorScale": "blue-red"
})
```

---

## MCP Tool Reference

### Tool: `mcp_sentinel-geom_show-attack-map`

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `data` | ✅ | array | Array of `{ip, lat, lon, value}` objects |
| `title` | ❌ | string | Title displayed above map (default: "Attack Origin Map") |
| `valueLabel` | ❌ | string | Label for values (default: "Attacks") |
| `colorScale` | ❌ | string | `blue-red` (threats), `green-red`, or `blue-yellow` |
| `enrichment` | ❌ | array | IP enrichment data for click-to-expand panels |

### Data Schema

```json
{
  "data": [
    {"ip": "101.36.107.228", "lat": 22.25, "lon": 114.15, "value": 44},
    {"ip": "193.142.147.209", "lat": 52.35, "lon": 4.92, "value": 13},
    {"ip": "170.64.158.196", "lat": -33.90, "lon": 151.19, "value": 9}
  ]
}
```

### Enrichment Schema

```json
{
  "enrichment": [
    {
      "ip": "101.36.107.228",
      "city": "Hong Kong",
      "country": "HK",
      "org": "AS135377 UCLOUD INFORMATION TECHNOLOGY",
      "is_vpn": true,
      "is_proxy": false,
      "is_tor": false,
      "abuse_confidence_score": 100,
      "total_reports": 4612,
      "last_reported": "2026-01-29",
      "threat_categories": ["SSH", "Brute-Force", "Web App Attack"]
    }
  ]
}
```

---

## ⚠️ CRITICAL: Complete Enrichment Requirement

**When providing enrichment data, ALWAYS include ALL IPs - never a subset.**

### Rule: 100% Enrichment Coverage

| Scenario | Correct Action |
|----------|----------------|
| Queried 50 IPs from Sentinel | Include enrichment for ALL 50 IPs |
| Enriched 25 IPs | Include ALL 25 in enrichment array |
| Some IPs failed enrichment | Include them with empty fields, or filter from both data AND enrichment |

### Why This Matters

- Users click markers expecting threat intel panels
- Missing enrichment = empty panels = broken UX
- Partial enrichment misleads security analysts

### Workflow to Ensure Complete Enrichment

1. **Query Sentinel** → Get N IPs with coordinates
2. **Batch enrich IPs** → `python enrich_ips.py <all_ips>` or `python enrich_ips.py --file <ips.json>`
3. **Parse enrichment JSON** → Extract ALL enriched entries
4. **Build enrichment array** → One entry per IP, matching `data` array exactly
5. **Call geomap** → Both `data` and `enrichment` arrays must have same IPs

### Example: Building Complete Enrichment

```python
import json

# Load enrichment from batch operation
with open('temp/ip_enrichment_<timestamp>.json', 'r') as f:
    raw_enrichment = json.load(f)

# Build geomap enrichment array - INCLUDE ALL
enrichment = []
for e in raw_enrichment:
    threat_cats = []
    for c in e.get('recent_comments', [])[:5]:
        threat_cats.extend(c.get('categories', []))
    
    enrichment.append({
        'ip': e['ip'],
        'city': e.get('city', 'Unknown'),
        'country': e.get('country', '??'),
        'org': e.get('org', 'Unknown'),
        'is_vpn': e.get('is_vpn') or e.get('vpnapi_security_vpn', False),
        'is_proxy': e.get('is_proxy') or e.get('vpnapi_security_proxy', False),
        'is_tor': e.get('is_tor') or e.get('vpnapi_security_tor', False),
        'abuse_confidence_score': e.get('abuse_confidence_score', 0),
        'total_reports': e.get('total_reports', 0),
        'last_reported': e.get('recent_comments', [{}])[0].get('date', '')[:10] if e.get('recent_comments') else '',
        'threat_categories': list(set(threat_cats))[:5]
    })

# Verify coverage
print(f"Enrichment entries: {len(enrichment)}")  # Must match data array length
```

### ❌ NEVER Do This

```python
# BAD: Only including first 25 IPs
enrichment = enrichment[:25]  # WRONG

# BAD: Skipping IPs without abuse scores
enrichment = [e for e in enrichment if e['abuse_confidence_score'] > 0]  # WRONG
```

### ✅ ALWAYS Do This

```python
# GOOD: Include all IPs, even if some fields are empty
enrichment = [transform(e) for e in raw_enrichment]  # All entries

# GOOD: If filtering, filter BOTH data and enrichment consistently
valid_ips = set(e['ip'] for e in enrichment if e.get('city'))
data = [d for d in data if d['ip'] in valid_ips]  # Filter both
```

---

## Data Sources

### Tables with Native Geolocation

Some Sentinel tables include lat/lon directly from Microsoft's GeoIP enrichment:

| Table | Latitude Column | Longitude Column | Country Column |
|-------|-----------------|------------------|----------------|
| **W3CIISLog** | `RemoteIPLatitude` | `RemoteIPLongitude` | `RemoteIPCountry` |
| **CommonSecurityLog** | `DeviceGeoLatitude` | `DeviceGeoLongitude` | `DeviceGeoCountry` |
| **AzureDiagnostics** | varies by source | varies by source | varies by source |
| **AzureNetworkAnalytics** | `SrcGeoLatitude` | `SrcGeoLongitude` | `SrcGeoCountry` |

**Use these when available** - no enrichment needed for coordinates.

### Tables Requiring IP Enrichment

These tables have IP addresses but **no coordinates**:

| Table | IP Column | Enrichment Required |
|-------|-----------|---------------------|
| **SigninLogs** | `IPAddress` | Yes - use `enrich_ips.py` |
| **SecurityEvent** | `IpAddress` | Yes - use `enrich_ips.py` |
| **Syslog** | extract from message | Yes - use `enrich_ips.py` |
| **DeviceNetworkEvents** | `RemoteIP` | Yes - use `enrich_ips.py` |
| **OfficeActivity** | `ClientIP` | Yes - use `enrich_ips.py` |

**Enrichment script now captures `latitude` and `longitude` from ipinfo.io.**

---

## KQL Query Patterns

### Pattern 1: Native Geolocation (W3CIISLog)

```kql
W3CIISLog
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where <filter_condition>
| summarize 
    value = count(),
    lat = take_any(RemoteIPLatitude),
    lon = take_any(RemoteIPLongitude),
    country = take_any(RemoteIPCountry)
    by ip = cIP
| where lat != 0 and lon != 0  // Filter unknown locations
| project ip, lat, lon, value
| order by value desc
```

### Pattern 2: Native Geolocation (CommonSecurityLog)

```kql
CommonSecurityLog
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where <filter_condition>
| summarize 
    value = count(),
    lat = take_any(DeviceGeoLatitude),
    lon = take_any(DeviceGeoLongitude)
    by ip = SourceIP
| where lat != 0 and lon != 0
| project ip, lat, lon, value
| order by value desc
```

### Pattern 3: Enrichment Required (Extract IPs Only)

```kql
<Table>
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where <filter_condition>
| summarize value = count() by ip = <IP_column>
| order by value desc
| take 100
```

Then run `enrich_ips.py` to get lat/lon.

---

## Scenario-Specific KQL Queries

### Scenario: W3CIISLog - Failed Logins (Native Geo)

```kql
W3CIISLog
| where TimeGenerated > ago(90d)
| where Computer startswith "<honeypot_name>"
| where scStatus == "401"  // Failed auth
| where cIP != "127.0.0.1"
| summarize 
    value = count(),
    lat = take_any(RemoteIPLatitude),
    lon = take_any(RemoteIPLongitude),
    country = take_any(RemoteIPCountry)
    by ip = cIP
| where lat != 0 and lon != 0
| project ip, lat, lon, value
| order by value desc
```

### Scenario: W3CIISLog - Web Attacks (Native Geo)

```kql
W3CIISLog
| where TimeGenerated > ago(30d)
| where tolong(scStatus) >= 400
| where csUriStem has_any ("'", "union", "select", "script", "../", "cmd.exe")
| where cIP != "127.0.0.1"
| summarize 
    value = count(),
    lat = take_any(RemoteIPLatitude),
    lon = take_any(RemoteIPLongitude)
    by ip = cIP
| where lat != 0
| project ip, lat, lon, value
| order by value desc
| take 100
```

### Scenario: CommonSecurityLog - Firewall Blocks (Native Geo)

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceAction == "Deny" or Activity has "blocked"
| summarize 
    value = count(),
    lat = take_any(DeviceGeoLatitude),
    lon = take_any(DeviceGeoLongitude)
    by ip = SourceIP
| where lat != 0 and lon != 0
| project ip, lat, lon, value
| order by value desc
| take 100
```

### Scenario: SigninLogs - Failed Sign-ins (Requires Enrichment)

**Step 1: Query IPs and values**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0  // Failed
| summarize value = count() by ip = IPAddress
| order by value desc
| take 50
```

**Step 2: Enrich IPs**
```powershell
python enrich_ips.py <ip1> <ip2> <ip3> ...
```

**Step 3: Build map data from enrichment JSON (includes lat/lon)**

### Scenario: SecurityEvent - RDP Brute Force (Requires Enrichment)

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| where LogonType == 10  // RDP
| where IpAddress != "-" and IpAddress != "127.0.0.1"
| summarize value = count() by ip = IpAddress
| order by value desc
| take 50
```

Then enrich to get coordinates.

### Scenario: DeviceNetworkEvents - Inbound Attacks (Requires Enrichment)

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where DeviceName =~ "<device_name>"
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| where LocalPort in (3389, 22, 445, 80, 443)
| where RemoteIP !startswith "192.168." and RemoteIP !startswith "10."
| summarize value = count() by ip = RemoteIP
| order by value desc
| take 50
```

---

## Enrichment Integration

### When Coordinates Are Not in Sentinel

For tables without native geo fields, use the enrichment script:

**Step 1:** Run your KQL query to get IPs and values

**Step 2:** Enrich IPs:
```powershell
python enrich_ips.py 203.0.113.42 198.51.100.10 192.0.2.1
# Or from file:
python enrich_ips.py --file temp/attack_ips.json
```

**Step 3:** Load enrichment JSON and build map data:
```python
import json

# Load enrichment (now includes latitude/longitude from ipinfo.io)
with open('temp/ip_enrichment_<timestamp>.json', 'r') as f:
    enrichment = json.load(f)

# Build map data
map_data = []
enrichment_out = []

for e in enrichment:
    ip = e['ip']
    lat = e.get('latitude')
    lon = e.get('longitude')
    
    if lat is None or lon is None:
        continue  # Skip IPs without coordinates
    
    # Get value from your KQL results (create a lookup dict)
    value = attack_counts.get(ip, 1)
    
    map_data.append({
        'ip': ip,
        'lat': lat,
        'lon': lon,
        'value': value
    })
    
    # Build enrichment for drill-down
    threat_cats = []
    for c in e.get('recent_comments', [])[:5]:
        threat_cats.extend(c.get('categories', []))
    
    enrichment_out.append({
        'ip': ip,
        'city': e.get('city', 'Unknown'),
        'country': e.get('country', '??'),
        'org': e.get('org', 'Unknown'),
        'is_vpn': e.get('is_vpn') or e.get('vpnapi_security_vpn', False),
        'abuse_confidence_score': e.get('abuse_confidence_score', 0),
        'total_reports': e.get('total_reports', 0),
        'last_reported': e.get('recent_comments', [{}])[0].get('date', '')[:10] if e.get('recent_comments') else '',
        'threat_categories': list(set(threat_cats))[:5]
    })
```

### Interactive Features with Enrichment

When enrichment is provided:
- **Click any marker** → Opens threat intel panel showing:
  - 📍 Location (city, country)
  - 🏢 Organization/ISP
  - 🏷️ VPN/Proxy/Tor badges
  - 📊 AbuseIPDB confidence meter
  - 📈 Total reports count
  - 🔴 Threat category tags

---

## Color Scale Guide

| Scale | Low Value | High Value | Best For |
|-------|-----------|------------|----------|
| `blue-red` | Blue | Red | **Threats** (attacks, failures) - DEFAULT |
| `green-red` | Teal | Green | Positive activity (benign traffic) |
| `blue-yellow` | Blue | Yellow | Neutral data distributions |

**For threat/attack maps, always use `blue-red`.**

---

## Complete Examples

### Example 1: 90-Day Honeypot Attack Map (Native Geo)

```
# 1. Query with native lat/lon from W3CIISLog
mcp_sentinel-data_query_lake({
  "query": "W3CIISLog | where TimeGenerated > ago(90d) | where Computer startswith '<HONEYPOT_SERVER>' | where scStatus == '401' | summarize value = count(), lat = take_any(RemoteIPLatitude), lon = take_any(RemoteIPLongitude), country = take_any(RemoteIPCountry) by ip = cIP | where lat != 0 and lon != 0 | project ip, lat, lon, value | order by value desc"
})

# 2. Enrich top IPs for threat intel drill-down
python enrich_ips.py 101.36.107.228 193.142.147.209 80.190.82.185

# 3. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [
    {"ip": "101.36.107.228", "lat": 22.25, "lon": 114.15, "value": 44},
    {"ip": "80.190.82.185", "lat": 50.97, "lon": 6.83, "value": 44},
    {"ip": "193.142.147.209", "lat": 52.35, "lon": 4.92, "value": 13},
    {"ip": "170.64.158.196", "lat": -33.9, "lon": 151.19, "value": 9}
  ],
  "title": "Honeypot Attack Origins - 90 Day Analysis",
  "valueLabel": "Failed Logins",
  "colorScale": "blue-red",
  "enrichment": [
    {"ip": "101.36.107.228", "city": "Hong Kong", "country": "HK", "org": "AS135377 UCLOUD", "is_vpn": true, "abuse_confidence_score": 100, "total_reports": 4612, "threat_categories": ["SSH", "Brute-Force"]},
    {"ip": "193.142.147.209", "city": "Amsterdam", "country": "NL", "org": "AS213438 ColocaTel", "is_vpn": true, "abuse_confidence_score": 100, "total_reports": 30973, "threat_categories": ["Web App Attack", "Hacking"]}
  ]
})
```

### Example 2: SigninLogs Attack Map (Enrichment Required)

```
# 1. Query IPs with failed sign-ins
mcp_sentinel-data_query_lake({
  "query": "SigninLogs | where TimeGenerated > ago(7d) | where ResultType != 0 | summarize value = count() by ip = IPAddress | order by value desc | take 50"
})

# 2. Enrich all IPs (script now captures lat/lon)
python enrich_ips.py <ip1> <ip2> ...

# 3. Load enrichment JSON and build map data
# (See Python code in Enrichment Integration section)

# 4. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [<map_data from enrichment>],
  "title": "Failed Sign-In Origins (Last 7 Days)",
  "valueLabel": "Failed Attempts",
  "colorScale": "blue-red",
  "enrichment": [<enrichment_out>]
})
```

### Example 3: Firewall Blocks (Native Geo)

```
# 1. Query blocked traffic with geo
mcp_sentinel-data_query_lake({
  "query": "CommonSecurityLog | where TimeGenerated > ago(24h) | where DeviceAction == 'Deny' | summarize value = count(), lat = take_any(DeviceGeoLatitude), lon = take_any(DeviceGeoLongitude) by ip = SourceIP | where lat != 0 | project ip, lat, lon, value | order by value desc | take 100"
})

# 2. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [<query results>],
  "title": "Blocked Traffic Origins (Last 24h)",
  "valueLabel": "Blocked Connections",
  "colorScale": "blue-red"
})
```

---

## Follow-Up Investigation Queries

When users select IPs from the geomap and click **"🔍 Investigate in Chat"**, run these queries to provide comprehensive threat analysis. Execute queries in parallel where possible.

### 🔧 Tool Selection: Data Lake vs Advanced Hunting

**CRITICAL:** Some tables exist only in Defender XDR Advanced Hunting, not in Sentinel Data Lake.

| Table | Tool to Use | Timestamp Column |
|-------|-------------|------------------|
| **SigninLogs** | `mcp_sentinel-data_query_lake` | `TimeGenerated` |
| **SecurityAlert** | `mcp_sentinel-data_query_lake` | `TimeGenerated` |
| **ThreatIntelIndicators** | `mcp_sentinel-data_query_lake` | `TimeGenerated` |
| **W3CIISLog** | `mcp_sentinel-data_query_lake` | `TimeGenerated` |
| **DeviceNetworkEvents** | `RunAdvancedHuntingQuery` ⚠️ | `Timestamp` |
| **SecurityEvent** | `RunAdvancedHuntingQuery` ⚠️ | `Timestamp` |
| **DeviceProcessEvents** | `RunAdvancedHuntingQuery` ⚠️ | `Timestamp` |
| **DeviceFileEvents** | `RunAdvancedHuntingQuery` ⚠️ | `Timestamp` |

**Note:** If a Data Lake query fails with "Failed to resolve table", retry with `RunAdvancedHuntingQuery`.

### Multi-IP Filter Pattern

All queries use this dynamic IP filter:
```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>", ...]);
```

Replace with the actual IPs selected from the geomap.

---

### Query 1: DeviceNetworkEvents (Network Activity) — Use Advanced Hunting

**Purpose:** Show all network connections from selected IPs to any device in the environment.

**Tool:** `RunAdvancedHuntingQuery` (NOT Data Lake)

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP in (target_ips)
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    TargetDevices = make_set(DeviceName, 10),
    TargetPorts = make_set(LocalPort, 20),
    Actions = make_set(ActionType, 5)
    by RemoteIP
| extend Duration = LastSeen - FirstSeen
| order by ConnectionCount desc
```

**Columns returned:**
- `RemoteIP`: Attacker IP
- `ConnectionCount`: Total connections
- `FirstSeen/LastSeen`: Activity time range
- `TargetDevices`: Devices contacted
- `TargetPorts`: Ports targeted (LocalPort = service ports on your devices)
- `Actions`: Connection types (Success, Blocked, etc.)

---

### Query 2: SecurityEvent (Windows Authentication) — Use Advanced Hunting

**Purpose:** Show Windows authentication attempts from selected IPs.

**Tool:** `RunAdvancedHuntingQuery` (NOT Data Lake) — SecurityEvent may not exist in Data Lake

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
SecurityEvent
| where Timestamp between (start .. end)
| where IpAddress in (target_ips)
| where EventID in (4624, 4625, 4648, 4771, 4776)
| summarize 
    EventCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    TargetComputers = make_set(Computer, 10),
    TargetAccounts = make_set(Account, 20),
    LogonTypes = make_set(LogonType, 5)
    by IpAddress, EventID
| extend EventType = case(
    EventID == 4624, "Successful Logon",
    EventID == 4625, "Failed Logon",
    EventID == 4648, "Explicit Credentials",
    EventID == 4771, "Kerberos Pre-Auth Failed",
    EventID == 4776, "NTLM Auth Attempt",
    "Other")
| project IpAddress, EventType, EventCount, TargetComputers, TargetAccounts, LogonTypes, FirstSeen, LastSeen
| order by EventCount desc
```

**Key Event IDs:**
- `4624`: Successful logon (ALERT: attacker got in!)
- `4625`: Failed logon (brute force indicator)
- `4648`: Explicit credentials used (lateral movement)
- `4771`: Kerberos pre-auth failed
- `4776`: NTLM credential validation

---

### Query 3: W3CIISLog (Web Attacks)

**Purpose:** Show HTTP requests from selected IPs including attack patterns.

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
W3CIISLog
| where TimeGenerated between (start .. end)
| where cIP in (target_ips)
| summarize 
    RequestCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetServers = make_set(Computer, 10),
    URIs = make_set(csUriStem, 20),
    StatusCodes = make_set(tolong(scStatus), 10),
    Methods = make_set(csMethod, 5),
    UserAgents = make_set(csUserAgent, 5)
    by cIP
| extend AttackPatterns = case(
    URIs has_any ("'", "union", "select"), "SQL Injection",
    URIs has "script", "XSS",
    URIs has_any ("../", "..\\"), "Path Traversal",
    URIs has_any ("cmd.exe", "powershell"), "Command Injection",
    "Reconnaissance")
| project IP = cIP, RequestCount, AttackPatterns, TargetServers, StatusCodes, Methods, URIs, FirstSeen, LastSeen
| order by RequestCount desc
```

---

### Query 4: SigninLogs (Azure AD Activity)

**Purpose:** Show Azure AD sign-in attempts from selected IPs.

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
SigninLogs
| where TimeGenerated between (start .. end)
| where IPAddress in (target_ips)
| summarize 
    SignInCount = count(),
    SuccessCount = countif(ResultType == 0),
    FailureCount = countif(ResultType != 0),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    TargetUsers = make_set(UserPrincipalName, 20),
    TargetApps = make_set(AppDisplayName, 10),
    ErrorCodes = make_set(ResultType, 10),
    ClientApps = make_set(ClientAppUsed, 5)
    by IPAddress
| extend SuccessRate = round(100.0 * SuccessCount / SignInCount, 1)
| project IPAddress, SignInCount, SuccessCount, FailureCount, SuccessRate, TargetUsers, TargetApps, ErrorCodes, FirstSeen, LastSeen
| order by SignInCount desc
```

**CRITICAL: Check SuccessCount > 0** - This indicates the attacker successfully authenticated!

---

### Query 5: ThreatIntelIndicators (Known Threats)

**Purpose:** Check if selected IPs match threat intelligence databases.

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
ThreatIntelIndicators
| extend IndicatorType = replace_string(replace_string(replace_string(tostring(split(ObservableKey, ":", 0)), "[", ""), "]", ""), "\"", "")
| where IndicatorType in ("ipv4-addr", "ipv6-addr", "network-traffic")
| extend NetworkSourceIP = toupper(ObservableValue)
| where NetworkSourceIP in (target_ips)
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| extend TrafficLightProtocolLevel = tostring(parse_json(AdditionalFields).TLPLevel)
| extend ActivityGroupNames = extract(@"ActivityGroup:(\S+)", 1, tostring(parse_json(Data).labels))
| summarize arg_max(TimeGenerated, *) by NetworkSourceIP
| project 
    IPAddress = NetworkSourceIP,
    ThreatDescription = Description,
    ActivityGroupNames,
    Confidence,
    ValidUntil,
    TrafficLightProtocolLevel,
    IsActive,
    TimeGenerated
| order by Confidence desc
```

**Key Fields:**
- `Confidence`: 0-100 threat confidence score
- `ActivityGroupNames`: APT/threat actor attribution (e.g., "PHOSPHORUS", "NOBELIUM")
- `ThreatDescription`: Details about the threat

---

### Query 6: SecurityAlert with Incident Status

**Purpose:** Find security alerts that reference selected IPs, with the **actual status from SecurityIncident** (not the immutable alert status).

**⚠️ IMPORTANT:** SecurityAlert.Status is immutable ("New" at creation time). The actual status is on the SecurityIncident table. This query joins to get the real incident status.

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
// Step 1: Find alerts containing target IPs as entities
let matched_alerts = SecurityAlert
| where TimeGenerated between (start .. end)
| extend EntitiesParsed = parse_json(Entities)
| mv-expand Entity = EntitiesParsed
| where Entity.["Type"] == "ip"
| extend EntityIP = tostring(Entity.Address)
| where EntityIP in (target_ips)
| summarize MatchedIPs = make_set(EntityIP) by SystemAlertId;
// Step 2: Get latest incident status for these alerts (keep AlertIds)
let incident_status = SecurityIncident
| where TimeGenerated between (start .. end)
| summarize arg_max(TimeGenerated, Status, Classification, IncidentNumber, AlertIds) by IncidentName
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| project AlertId, IncidentStatus = Status, Classification, IncidentNumber;
// Step 3: Join alerts with matched IPs and incident status
SecurityAlert
| where TimeGenerated between (start .. end)
| where SystemAlertId in (matched_alerts)
| join kind=leftouter matched_alerts on $left.SystemAlertId == $right.SystemAlertId
| join kind=leftouter incident_status on $left.SystemAlertId == $right.AlertId
| summarize arg_max(TimeGenerated, AlertName, AlertSeverity, Status, ProviderName, Tactics, Description, MatchedIPs, IncidentStatus, Classification, IncidentNumber) by SystemAlertId
| extend FinalStatus = coalesce(IncidentStatus, Status)  // Use incident status if available
| project 
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Status = FinalStatus,
    Classification,
    IncidentNumber,
    ProviderName,
    Tactics,
    MatchedIPs,
    Description
| order by TimeGenerated desc
| take 25
```

**Why This Matters:**
- SecurityAlert.Status = "New" is the **creation status** (immutable)
- SecurityIncident.Status shows the **current status** (New/Active/Closed)
- SecurityIncident.Classification shows the **closure reason** (TruePositive/FalsePositive/BenignPositive)
- Alerts without incidents keep their original "New" status

**Entities JSON Structure Example:**
```json
[
  {"$id":"3","HostName":"contoso-server","Type":"host"},
  {"$id":"4","Address":"203.0.113.10","Type":"ip"},
  {"$id":"5","Address":"198.51.100.20","Type":"ip"}
]
```

---

### Query 7: DeviceProcessEvents (Process Execution Post-Compromise) — Use Advanced Hunting

**Purpose:** If attacker IPs had successful connections, check for suspicious process execution.

**Tool:** `RunAdvancedHuntingQuery` (NOT Data Lake)

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
// First, find devices that had connections from target IPs
let compromised_devices = DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP in (target_ips)
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| distinct DeviceName;
// Then check for suspicious processes on those devices
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in (compromised_devices)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe")
    or ProcessCommandLine has_any ("Invoke-", "IEX", "DownloadString", "WebClient", "-enc", "-encoded", "bypass", "hidden")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
| take 50
```

---

### Query 8: DeviceFileEvents (Malware Drops) — Use Advanced Hunting

**Purpose:** Check for file creation/modification on devices contacted by attacker IPs.

**Tool:** `RunAdvancedHuntingQuery` (NOT Data Lake)

```kql
let target_ips = dynamic(["<IP1>", "<IP2>", "<IP3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
// Find devices that had connections from target IPs
let compromised_devices = DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP in (target_ips)
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| distinct DeviceName;
// Check for suspicious file activity
DeviceFileEvents
| where Timestamp between (start .. end)
| where DeviceName in (compromised_devices)
| where ActionType in ("FileCreated", "FileModified")
| where FileName endswith_cs ".exe" or FileName endswith_cs ".dll" or FileName endswith_cs ".ps1" 
    or FileName endswith_cs ".bat" or FileName endswith_cs ".vbs" or FileName endswith_cs ".js"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\ProgramData\\", "\\Users\\Public\\")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, SHA256
| order by Timestamp desc
| take 50
```

---

### Recommended Execution Order

When user selects IPs and clicks "Investigate in Chat":

**Phase 1 (Parallel) — Data Lake queries:**
- Query 3: W3CIISLog → `mcp_sentinel-data_query_lake`
- Query 4: SigninLogs → `mcp_sentinel-data_query_lake`
- Query 5: ThreatIntelIndicators → `mcp_sentinel-data_query_lake`
- Query 6: SecurityAlert → `mcp_sentinel-data_query_lake`

**Phase 1 (Parallel) — Advanced Hunting queries:**
- Query 1: DeviceNetworkEvents → `RunAdvancedHuntingQuery`
- Query 2: SecurityEvent → `RunAdvancedHuntingQuery`

**Phase 2 (If connections found) — Advanced Hunting:**
- Query 7: DeviceProcessEvents → `RunAdvancedHuntingQuery`
- Query 8: DeviceFileEvents → `RunAdvancedHuntingQuery`

**Response Format:**

Summarize findings with:
1. **Threat Level Assessment** (Critical/High/Medium/Low)
2. **Attack Summary** - What the IPs did, which devices/users were targeted
3. **Successful Access** - ALERT if any successful logins (4624) or Azure AD success (ResultType=0)
4. **Threat Intel Matches** - Known APT groups, malware campaigns
5. **Recommendations** - Block IPs, investigate users, isolate devices

---

## Interactive Selection Feature

The geomap supports multi-select mode for follow-up investigations:

### How to Use

1. **Click "☑ Select" button** (top of map) to enter selection mode
2. **Click markers** to add/remove IPs from selection (green checkmark ✓)
3. **Review selection panel** showing selected IPs with enrichment summary
4. **Click "🔍 Investigate in Chat"** to send selected IPs for investigation

### What Happens

When you click "Investigate in Chat":
1. All selected IPs are formatted with enrichment context
2. Message is sent to chat as a user message
3. LLM runs the follow-up queries above automatically
4. Results are summarized with threat assessment

### Selection Panel Shows

For each selected IP:
- IP address
- City, Country
- Abuse confidence score (color-coded badge)
- Attack value from the map

---

## Technical Notes

- **Projection:** Robinson projection for accurate world map display
- **Map Source:** SimpleMaps.com world SVG (MIT license)
- **Bundle Size:** ~650 KB (includes embedded world map)
- **CSP Compliance:** No external resources - all assets embedded inline
- **Coordinate System:** Standard WGS84 (latitude: -90 to 90, longitude: -180 to 180)

---

## When to Use Geomaps

✅ **Good Use Cases:**
- Attack origin visualization (honeypots, firewalls)
- Geographic threat distribution
- Anomalous sign-in locations
- VPN/anonymization analysis across regions
- Executive briefings on global threats

❌ **Skip Geomaps When:**
- Fewer than 3 unique locations (too sparse)
- All IPs from same region (use heatmap instead)
- Time-based patterns needed (use heatmap)
- No geographic data available and enrichment not feasible

---

*Last Updated: February 1, 2026*
