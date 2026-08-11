# Invoke-MailboxPermissionCleaner

Removes mailbox-related permissions from Exchange `UserMailbox` recipients whose owner account is **disabled**, and optionally removes orphaned (SID-only) permissions from all mailboxes in Exchange on-premises mode.

## Overview

`Invoke-MailboxPermissionCleaner.ps1` is a production-ready PowerShell 5.1+ script that supports both **Exchange on-premises** and **Exchange Online** in one unified script. It discovers all `UserMailbox` recipients, checks whether the owner account is disabled, and removes selected permission types. Use `-WhatIf` to preview findings on screen without making changes.

At startup, the script auto-detects whether it runs in Exchange on-premises or Exchange Online.

| Permission type | Cmdlets used |
|---|---|
| Full Access | `Get-MailboxPermission` / `Remove-MailboxPermission` |
| Send As (On-premises) | `Get-ADPermission` / `Remove-ADPermission` |
| Send As (Exchange Online) | `Get-RecipientPermission` / `Remove-RecipientPermission` |
| Send On Behalf | `Set-Mailbox -GrantSendOnBehalfTo @{ Remove = … }` |
| Calendar folder | `Get-MailboxFolderPermission` / `Remove-MailboxFolderPermission` |

All removal attempts are written to a timestamped CSV log file, including `-WhatIf` runs.

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| Exchange Management Shell / Exchange Online | Exchange Server 2013, 2016, 2019, or Exchange Online PowerShell session |
| ActiveDirectory module | Required in on-premises mode only (`RSAT-AD-PowerShell` feature or equivalent) |
| Exchange permissions | Organization Management or equivalent (read + remove mailbox permissions) |

Run from either an Exchange Management Shell session (on-premises) or a connected Exchange Online PowerShell session (cloud).

---

## Usage

```powershell
# Dry run with -WhatIf – simulate removals and emit findings to the pipeline while also writing to the CSV log
.\Invoke-MailboxPermissionCleaner.ps1 -WhatIf

# Dry run piped to grid view – interactively review all findings
.\Invoke-MailboxPermissionCleaner.ps1 -WhatIf | Out-GridView

# Dry run with verbose output – simulate removals with detailed progress
.\Invoke-MailboxPermissionCleaner.ps1 -WhatIf -Verbose

# Production run against all mailboxes (all four permission types, disabled owners only)
.\Invoke-MailboxPermissionCleaner.ps1

# Specify a custom log path and limit to the first 500 mailboxes
.\Invoke-MailboxPermissionCleaner.ps1 -LogPath C:\Logs\cleanup.csv -ResultSize 500

# Remove only Full Access and Send As permissions for disabled-owner mailboxes
.\Invoke-MailboxPermissionCleaner.ps1 -FullAccess -SendAs

# Remove orphaned SID entries from all mailboxes (Full Access and Calendar only)
.\Invoke-MailboxPermissionCleaner.ps1 -Orphan -FullAccess -Calendar

# Report orphaned Full Access entries across all mailboxes, export to CSV
.\Invoke-MailboxPermissionCleaner.ps1 -WhatIf -Orphan -FullAccess |
    Export-Csv -Path C:\Reports\orphans.csv -NoTypeInformation
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-LogPath` | `String` | `Invoke-MailboxPermissionCleaner-<yyyyMMdd_HHmmss>.csv` in CWD | Full path to the CSV log file. Appends if the file already exists. |
| `-ResultSize` | `String` | `Unlimited` | Maximum number of mailboxes returned by `Get-Mailbox`. |
| `-FullAccess` | `Switch` | *(see note)* | Process Full Access (`MailboxPermission`) entries. |
| `-SendAs` | `Switch` | *(see note)* | Process Send As (`ADPermission`) entries. |
| `-SendOnBehalfOf` | `Switch` | *(see note)* | Process Send On Behalf Of (`GrantSendOnBehalfTo`) entries. |
| `-Calendar` | `Switch` | *(see note)* | Process Calendar folder (`MailboxFolderPermission`) entries. |
| `-Orphan` | `Switch` | `$false` | On-premises only. Removes unresolvable SID trustees from **all** mailboxes, regardless of owner state. In Exchange Online, this switch is ignored with a notice. |
| `-WhatIf` | `Switch` | — | Simulate all removals. Findings are written to the pipeline and also written to the CSV log file; output can be piped to `Out-GridView`, `Export-Csv`, etc. |
| `-Confirm` | `Switch` | — | Prompt before each removal operation. |
| `-Verbose` | `Switch` | — | Write detailed progress information to the console. |

> **Permission-type switch default:** When none of `-FullAccess`, `-SendAs`, `-SendOnBehalfOf`, or `-Calendar` are specified, all four are processed automatically (backward-compatible default).

---

## Behaviour Details

### Special permissions (always skipped)

The following permissions are always skipped and never removed, regardless of mailbox owner state, trustee state, or orphan status:

- **NT AUTHORITY\SELF** — a special Windows permission that represents the object itself. This permission is automatically managed by Exchange and should not be modified.
- **Calendar Default and Anonymous** — built-in calendar permissions maintained by Exchange.

---

### Disabled-owner and disabled-trustee mode (always active)

The script removes permission entries in two scenarios:

1. **Disabled mailbox owner** — For every mailbox whose AD owner account is disabled, all permission entries of the selected types are removed. Disabled accounts are no longer legitimate delegates.
2. **Disabled trustee/delegate** — For every permission entry found, if the trustee (delegate) account is disabled in AD, that entry is removed regardless of the mailbox owner's state. This ensures that disabled users cannot retain access or delegation rights through existing permissions.

The rationale is that disabled accounts pose a security and compliance risk and should not maintain any active permissions on mailboxes.

### -Orphan mode

When `-Orphan` is specified in **on-premises mode**, the script additionally scans **every** mailbox (regardless of owner state) for trustees that resolve to a raw Windows SID (e.g. `S-1-5-21-1234567890-...`). These orphaned entries indicate the original account has been permanently deleted from Active Directory. They are removed and logged with `Reason = "Orphaned SID trustee - <type> cleanup"`.

In **Exchange Online mode**, orphan SID detection is not supported. The script writes a notice and continues with orphan handling disabled.

The `-FullAccess`, `-SendAs`, and `-Calendar` switches control which permission types are inspected for orphans. `-SendOnBehalfOf` is excluded because those entries are stored as Distinguished Names, not SIDs.

```powershell
# Simulate orphan cleanup for Full Access and Calendar across all mailboxes
.\Invoke-MailboxPermissionCleaner.ps1 -Orphan -FullAccess -Calendar -WhatIf
```

### -WhatIf mode

When `-WhatIf` is specified:

- **No Exchange or AD changes are made** — all removal cmdlets are skipped.
- **CSV log file is still written** — findings are appended to the `-LogPath` CSV for auditability.
- **Findings are written to the pipeline** as `PSCustomObject` instances with the same columns as the CSV log. These can be piped to `Out-GridView`, `Export-Csv`, `Format-Table`, etc.
- `RemovedAction` is set to `WhatIf` for every finding.

`-WhatIf` is the preferred first step before running in production: it lets you review exactly what *would* be removed and export those findings to file or screen for approval.

### Multi-Forest / Linked Mailbox Support

In on-premises environments where mailboxes live in a dedicated Exchange resource forest and owner accounts live in a separate accounts forest, Exchange cmdlets may only see the local forest by default. At startup the script calls `Get-ADForest` and automatically enables `Set-ADServerSettings -ViewEntireForest $true` when the forest contains more than one domain. No switch or manual configuration is required.

If `Get-ADForest` cannot be reached, a warning is written and the script continues — ViewEntireForest will remain at its current session value.

---

## CSV Log

### Columns

| Column | Description |
|---|---|
| `Timestamp` | Date and time the entry was written (`yyyy-MM-dd HH:mm:ss`) |
| `MailboxDisplayName` | Display name of the mailbox |
| `MailboxPrimarySmtpAddress` | Primary SMTP address of the mailbox |
| `MailboxOwnerSamAccountName` | `sAMAccountName` of the mailbox owner |
| `MailboxOwnerUPN` | UPN of the mailbox owner |
| `MailboxRecipientType` | Recipient type details (e.g. `UserMailbox`) |
| `TrusteeOriginal` | Raw trustee string as returned by the permission cmdlet |
| `TrusteeResolvedUPN` | Resolved UPN of the trustee (empty if unresolvable) |
| `PermissionType` | `FullAccess` \| `SendAs` \| `SendOnBehalf` \| `CalendarPermission` |
| `RemovedAction` | `Removed` \| `Failed` \| `WhatIf` |
| `Reason` | Human-readable reason for removal |
| `Success` | `True` or `False` |
| `ErrorMessage` | Error detail when `Success = False` |

### RemovedAction values

| Value | Meaning |
|---|---|
| `Removed` | Permission was successfully removed |
| `Failed` | Removal was attempted but an error occurred |
| `WhatIf` | Script was run with `-WhatIf`; no change was made and findings were emitted to the pipeline |

---

## Architecture

### Caching

Five script-scoped hashtables are populated lazily to avoid redundant lookups:

| Cache | Key | Value |
|---|---|---|
| `$script:TrusteeCache` | Raw trustee string | Resolved UPN or sentinel |
| `$script:RecipientCache` | Identity string | `Get-Recipient` result or sentinel |
| `$script:ADUserCache` | Identity string | `Get-ADUser` result or sentinel |
| `$script:TrusteeDisabledCache` | Resolved UPN | `$true` (disabled) \| `$false` (enabled) \| sentinel (not a user) |
| `$script:CalendarCache` | Mailbox identity | Calendar folder path string |

A sentinel value (`__NOT_FOUND__`) is stored for failed lookups so the external call is never retried for the same input.

**User-only filtering:** Trustee disabled state is determined by querying Active Directory for **user accounts only**. When a trustee is resolved to a UPN, `Test-TrusteeIsDisabled` attempts `Get-ADUser`, which only matches user objects, not groups. If the object is a group, the lookup fails and the trustee is treated as enabled (groups are not subject to removal). This ensures that group-based permissions are preserved, while user accounts are properly evaluated for disabled state.

### Localized Calendar Discovery

Exchange stores the calendar folder name in the mailbox language (`Kalender` in Dutch, `Calendrier` in French, etc.). The script uses `Get-MailboxFolderStatistics` and selects the folder where `FolderType -eq 'Calendar'`, then constructs the `<alias>:\<FolderPath>` identifier required by `*-MailboxFolderPermission`.

### Trustee Resolution

Permissions may expose trustees in multiple formats: sAMAccountName (e.g., `testuser`), `DOMAIN\sAMAccountName` (e.g., `AD\testuser`), slash-separated DN (e.g., `ad.myexchangelabs.com/NL/testuser`), Distinguished Name, SID, Alias, or LegacyExchangeDN. The internal `Resolve-Trustee` function normalizes all formats and:

1. Checks the in-memory `$script:TrusteeCache`.
2. Calls `Get-Recipient` (handles normalized identity, DN, LegacyExchangeDN, SMTP address). If successful, extracts the **DistinguishedName** (or falls back to PrimarySmtpAddress) for compatibility with `Get-ADUser -Identity`.
3. Falls back to `Get-ADUser` (SamAccountName, SID, or DN).
4. Returns a `PSCustomObject` with `OriginalValue`, `ResolvedUPN`, and `IsOrphanSid`.

Format normalization:
- `DOMAIN\sAMAccountName` → extract `sAMAccountName`
- `domain.com/OU/sAMAccountName` → extract last component (`sAMAccountName`)
- `sAMAccountName` → use as-is
- `DN`, `SID`, `GUID` → use as-is

The resolved identity must be compatible with `Get-ADUser -Identity`, which accepts: UPN, SamAccountName, DistinguishedName, GUID, or SID. This is critical for `Test-TrusteeIsDisabled` to correctly identify disabled trustee accounts.

A trustee is flagged as an orphaned SID when all resolution attempts fail **and** the raw value matches the pattern `^S-1-\d+-\d+(-\d+)+$`.

### Implicit Remoting Compatibility

When Exchange cmdlets are used via an imported remote session (implicit remoting), objects returned by `Get-Mailbox` are deserialized as `Deserialized.Microsoft.Exchange.Data.*` types. These cannot be passed back to Exchange cmdlets as `-Identity` parameters because the parameter binder cannot reconstruct the original type.

All removal functions resolve the mailbox identity to a plain string (`$Mailbox.PrimarySmtpAddress.ToString()`) before passing it to any Exchange cmdlet. This ensures the script works correctly whether run directly in an EMS console or via an imported remote session.

---

## License

See [LICENSE](LICENSE).
