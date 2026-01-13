---
name: ca-policy-investigation
description: Use this skill when asked to investigate Conditional Access policy changes, sign-in failures related to CA policies (error codes 53000, 50074, 530032), or suspected policy bypass/manipulation. Triggers on keywords like "Conditional Access", "CA policy", "device compliance", "policy bypass", "53000", "50074", or when investigating why a user was blocked then suddenly unblocked. This skill provides forensic analysis of CA policy modifications correlated with sign-in failures.
---

# Conditional Access Policy Investigation - Instructions

## Purpose

This skill investigates Conditional Access (CA) policy changes in correlation with sign-in failures to detect:
- **Legitimate troubleshooting** (authorized policy changes to resolve access issues)
- **Security control bypass** (unauthorized policy modifications to circumvent blocks)
- **Privilege abuse** (users with admin rights weakening security controls)

The key distinction is whether policy changes were **authorized and necessary** vs **self-service bypass of security controls**.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Investigation Rules](#critical-investigation-rules)** - Mandatory workflow steps
2. **[Common Error Codes](#common-error-codes)** - Sign-in failure reference
3. **[CA Policy States](#ca-policy-state-meanings)** - Understanding policy modes
4. **[5-Step Investigation Workflow](#investigation-workflow-pattern)** - KQL queries and analysis
5. **[Real-World Example](#real-world-example-analysis)** - Complete walkthrough
6. **[Critical Mistakes](#critical-mistakes-to-avoid)** - What NOT to do
7. **[Security Recommendations](#security-recommendations)** - Remediation guidance

---

## Critical Investigation Rules

When investigating sign-in failures (error codes 53000, 50074) with CA policy correlation:

**⚠️ MANDATORY STEPS - DO NOT SKIP:**

1. **Query ALL CA policy changes in chronological order** (±2 days from failure time)
2. **Parse policy state transitions** from the JSON (enabled → disabled → report-only)
3. **Compare failure timeline with policy change timeline**
4. **Verify logical consistency**: Ask "does this make sense?"

**Key Questions to Answer:**
- Was the user blocked BEFORE the policy change?
- Did the policy change resolve the block?
- Who initiated the policy change? (same user = suspicious)
- What was the business justification?

---

## Common Error Codes

| Error Code | Description | Typical Cause |
|------------|-------------|---------------|
| **53000** | Device not compliant | Device not enrolled in Intune or failing compliance checks |
| **50074** | Strong authentication required | MFA not satisfied |
| **50074** | User must enroll in MFA | MFA not configured for user |
| **530032** | Blocked by CA policy | Generic CA policy block |
| **65001** | User consent required | Application consent needed |
| **53003** | Access blocked by CA policy | Explicit block condition met |
| **70044** | Session expired | User needs to re-authenticate |

### Error Code Investigation Priority

| Priority | Error Codes | Investigation Focus |
|----------|-------------|---------------------|
| **HIGH** | 53000, 530032, 53003 | Device compliance, CA policy blocks - check for policy manipulation |
| **MEDIUM** | 50074 | MFA requirements - check if MFA was bypassed |
| **LOW** | 65001, 70044 | Consent/session issues - usually not security-related |

---

## CA Policy State Meanings

| State | What It Means | Security Impact |
|-------|---------------|----------------|
| **enabled** | Policy actively enforcing | Blocks non-compliant access (intended behavior) |
| **disabled** | Policy not enforcing | **Security control bypassed** - all access allowed |
| **enabledForReportingButNotEnforced** | Report-only mode | Logs violations but **doesn't block** - defeats purpose |

### State Transition Risk Assessment

| Transition | Risk Level | Interpretation |
|------------|------------|----------------|
| `enabled` → `disabled` | **HIGH** | Complete security bypass |
| `enabled` → `enabledForReportingButNotEnforced` | **MEDIUM-HIGH** | Partial bypass (monitoring only) |
| `disabled` → `enabled` | **LOW** | Security restored (good) |
| `enabledForReportingButNotEnforced` → `enabled` | **LOW** | Security strengthened (good) |

---

## Investigation Workflow Pattern

### Step 1: Identify Sign-In Failures

**Query sign-in failures with CA context:**

```kql
// Get failures with CA context
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| where AppDisplayName has '<APPLICATION>'  // e.g., "Visual Studio Code"
| project TimeGenerated, IPAddress, Location, ResultType, ResultDescription, 
    ConditionalAccessStatus, UserAgent
| order by TimeGenerated asc
```

**What to Look For:**
- `ResultType` values: 53000, 50074, 530032, 53003
- `ConditionalAccessStatus`: "failure", "notApplied"
- Pattern of repeated failures followed by success

---

### Step 2: Query ALL CA Policy Changes in Timeframe

**CRITICAL: Query ±2 days from the first failure time**

```kql
let failure_time = datetime(<FIRST_FAILURE_TIME>);
let start = failure_time - 2d;
let end = failure_time + 2d;
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has_any ("Conditional Access", "policy")
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| extend InitiatorUPN = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend InitiatorIPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| extend TargetName = tostring(parse_json(TargetResources)[0].displayName)
| project TimeGenerated, OperationName, Result, InitiatorUPN, InitiatorIPAddress, 
    TargetName, CorrelationId
| order by TimeGenerated asc  // CRITICAL: Chronological order
```

**Critical Analysis Points:**
- **InitiatorUPN**: Who made the change? Same user as blocked = suspicious
- **TargetName**: Which policy was modified?
- **TimeGenerated**: Did change occur AFTER sign-in failures?
- **Order**: Always chronological (oldest first) to see cause/effect

---

### Step 3: Parse Policy State Changes

**For each CorrelationId from Step 2, get detailed changes:**

```kql
// Get detailed property changes for a specific policy modification
AuditLogs
| where CorrelationId == "<CORRELATION_ID>"
| extend ModifiedProperties = parse_json(TargetResources)[0].modifiedProperties
| mv-expand ModifiedProperties
| extend PropertyName = tostring(ModifiedProperties.displayName)
| extend OldValue = tostring(ModifiedProperties.oldValue)
| extend NewValue = tostring(ModifiedProperties.newValue)
| project TimeGenerated, PropertyName, OldValue, NewValue
```

**Key Properties to Extract:**
- Look for `"state"` property in the JSON
- Parse `OldValue` and `NewValue` for state transitions
- Document: `enabled` → `disabled` → `enabledForReportingButNotEnforced`

---

### Step 4: Extract Policy State from JSON

**Manual JSON Parsing:**

The `OldValue` and `NewValue` fields contain JSON. Look for the `"state"` field:

```json
{
  "state": "enabled",
  "conditions": { ... },
  "grantControls": { ... }
}
```

**Build the Timeline:**
1. Extract `"state"` from each `OldValue` and `NewValue`
2. Create chronological list: `enabled` → `disabled` → `enabledForReportingButNotEnforced`
3. Correlate with sign-in failure timeline

---

### Step 5: Security Assessment

**Compare timelines and assess intent:**

| Pattern | Interpretation | Risk Level |
|---------|----------------|------------|
| **Failures → Policy Disabled** | User bypassed security control to unblock self | **HIGH** - Privilege abuse |
| **Failures → Policy Changed to Report-Only** | User weakened security control | **MEDIUM-HIGH** - Partial bypass |
| **Policy Disabled → Failures Continue** | Cached tokens (5-15 min propagation delay) | **INFO** - Expected behavior |
| **Policy Changed → No More Failures** | Policy change resolved issue | **Context-dependent** - May be legitimate troubleshooting |
| **Different user made change** | Admin assisted with access issue | **LOW** - Likely legitimate (verify authorization) |

**Risk Escalation Criteria:**

| Criteria | Risk Level |
|----------|------------|
| Same user blocked AND made policy change | **HIGH** |
| Policy disabled within 30 minutes of first failure | **HIGH** |
| Multiple policies modified | **HIGH** |
| Change made outside business hours | **MEDIUM-HIGH** |
| No change request ticket/approval | **MEDIUM-HIGH** |
| Admin made change for blocked user (with ticket) | **LOW** |

---

## Real-World Example Analysis

**Scenario:** User blocked by device compliance policy, then modifies policy

### Timeline

| Time | Event | Details |
|------|-------|---------|
| 19:05 | Sign-in failure | Error 53000: device not compliant |
| 19:06 | Sign-in failure | Error 53000: device not compliant |
| 19:07 | Sign-in failure | Error 53000: device not compliant |
| 19:09 | Policy change | `enabled` → `disabled` |
| 19:09 | Policy change | `disabled` → `enabledForReportingButNotEnforced` |
| 19:12 | Sign-in failure | Error 53000 (cached token) |
| 19:14 | Sign-in success | Access granted |

### Analysis

1. ✅ **Policy was correctly blocking non-compliant device**
   - Device compliance policy was enforcing as intended
   - User's device failed compliance checks (not enrolled or failing policy)

2. 🚨 **User disabled security control to bypass block**
   - Same user who was blocked made the policy change
   - Change occurred within 4 minutes of repeated failures
   - No approval or change request documented

3. ⚠️ **User partially reversed by enabling report-only**
   - Shows some awareness that disabling was too aggressive
   - But report-only still defeats the purpose (doesn't block)

4. ❌ **Report-only mode is NOT a valid security posture**
   - Logs violations but allows non-compliant access
   - Creates false sense of security (policy "exists" but doesn't protect)

### Assessment

| Field | Value |
|-------|-------|
| **Risk Level** | MEDIUM-HIGH |
| **Finding** | Self-service security bypass using privileged role |
| **Root Cause** | User's device is non-compliant (not enrolled/failing compliance) |
| **Policy Impact** | Device compliance checks now ineffective for all users |

### Recommendations

1. **Immediate Actions:**
   - Restore policy to `enabled` state
   - Verify user's device compliance status
   - Document incident for security review

2. **User-Specific:**
   - Enroll user's device in Intune
   - Verify device meets compliance requirements
   - Review if user needs Security Administrator role

3. **Process Improvements:**
   - Implement approval workflow for CA policy changes
   - Create alert for policy state changes (enabled → disabled/report-only)
   - Review all users with permission to modify CA policies
   - Consider PIM for Security Administrator role

---

## Critical Mistakes to Avoid

### ❌ DON'T:

| Mistake | Why It's Wrong |
|---------|----------------|
| Query only ONE policy change event | You'll miss the sequence of changes |
| Read policy changes in reverse chronological order | Confuses cause/effect relationship |
| Assume policy was already disabled | Must check starting state from `OldValue` |
| Skip verifying "does this make logical sense?" | Disabled policies can't block users |
| Ignore the initiator identity | Same user = suspicious, different admin = verify authorization |
| Focus only on final state | The transition sequence reveals intent |

### ✅ DO:

| Best Practice | Why It Matters |
|---------------|----------------|
| Query ALL policy changes in the timeframe | Complete picture of modifications |
| Order chronologically (oldest first) | See cause/effect sequence |
| Parse the full JSON for state transitions | Extract exact policy states |
| Cross-check: blocked user → policy must be enabled | Logical consistency verification |
| Ask: "Why would user disable this policy?" | Usually to bypass a legitimate block |
| Check if initiator had authorization | Ticket, approval, documented reason |

---

## Security Recommendations

### When CA Policy Changes Are Detected

#### 1. Determine Legitimacy

- Was the policy change authorized?
- Was there a valid business reason?
- Did the user have approval to make this change?
- Is there a change request ticket?

#### 2. Assess Impact

- How many users affected by policy change?
- What applications/resources are now unprotected?
- How long was the policy disabled/weakened?
- Are there compliance implications (regulatory requirements)?

#### 3. Remediation Actions

| Action | Priority |
|--------|----------|
| Restore policy to `enabled` state if unauthorized | **IMMEDIATE** |
| Investigate root cause (why was user blocked?) | **HIGH** |
| Fix underlying issue (device compliance, MFA enrollment) | **HIGH** |
| Review who has permission to modify CA policies | **MEDIUM** |
| Implement approval workflows for policy changes | **MEDIUM** |
| Create alerts for future CA policy modifications | **MEDIUM** |

#### 4. Long-Term Improvements

| Improvement | Benefit |
|-------------|---------|
| Use PIM for Security Administrator role | Requires approval for elevated access |
| Implement CA policy change alerts | Real-time notification of modifications |
| Require multi-admin approval for state changes | Prevents single-person bypass |
| Document approved procedures | Clear guidance for legitimate troubleshooting |
| Regular access reviews | Ensure only necessary users have CA admin rights |

---

## Prerequisites

### Required MCP Servers

This skill requires:

1. **Microsoft Sentinel MCP** - For KQL queries against SigninLogs and AuditLogs
   - `mcp_sentinel-data_query_lake`: Execute KQL queries
   - `mcp_sentinel-data_search_tables`: Discover table schemas

### Required Data Sources

- **SigninLogs** - Interactive sign-in events with CA status
- **AADNonInteractiveUserSignInLogs** - Non-interactive sign-in events
- **AuditLogs** - CA policy modification events

### Required Permissions

To view CA policy changes in AuditLogs, ensure:
- Sentinel workspace has AuditLogs ingestion enabled
- User has appropriate RBAC to query the workspace

---

## Integration with Other Skills

CA Policy Investigation often follows a **user-investigation**:

1. **Run user-investigation skill** → Identifies sign-in failures
2. **Notice CA-related error codes** → 53000, 50074, 530032
3. **Run ca-policy-investigation skill** → Correlate failures with policy changes
4. **Document findings** → Security assessment with remediation recommendations

**Key Integration Points:**
- Sign-in failure data comes from user investigation
- CA policy changes are NEW queries specific to this skill
- Assessment combines timeline correlation with policy state analysis
