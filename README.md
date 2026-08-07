# Invoke-MailboxPermissionCleaner

Removes mailbox-related permissions from Exchange on-premises `UserMailbox` recipients whose Active Directory owner account is **disabled**, preventing shared mailboxes, calendars, and delegated folders from re-appearing after profile recreation.

## Overview

`Invoke-MailboxPermissionCleaner.ps1` is a production-ready PowerShell 5.1+ script designed to run from an **Exchange Management Shell (EMS)** session.  It discovers all `UserMailbox` recipients, checks whether the owning AD account is disabled, and – for each disabled owner – removes:

| Permission type | Cmdlets used |
|---|---|
| Full Access | `Get-MailboxPermission` / `Remove-MailboxPermission` |
| Send As | `Get-ADPermission` / `Remove-ADPermission` |
| Send On Behalf | `Set-Mailbox -GrantSendOnBehalfTo @{ Remove = … }` |
| Calendar folder | `Get-MailboxFolderPermission` / `Remove-MailboxFolderPermission` |

All removal attempts are written to a CSV log file.

---

## Requirements

- PowerShell 5.1 or later
- Exchange Management Shell (EMS) – Exchange 2013, 2016, or 2019
- `ActiveDirectory` PowerShell module (`RSAT-AD-PowerShell` or equivalent)
- Exchange **Organization Management** (or equivalent) permissions

---

## Usage

```powershell
# Dry run – no changes are made
.\Invoke-MailboxPermissionCleaner.ps1 -WhatIf -Verbose

# Production run against all mailboxes
.\Invoke-MailboxPermissionCleaner.ps1

# Specify a custom log path and limit scope to 500 mailboxes
.\Invoke-MailboxPermissionCleaner.ps1 -LogPath C:\Logs\cleanup.csv -ResultSize 500
```

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-LogPath` | `MailboxPermissionCleaner_<timestamp>.csv` in CWD | Path to the CSV log file |
| `-ResultSize` | `Unlimited` | Maximum mailboxes returned by `Get-Mailbox` |
| `-FullAccess` | (see note) | Process Full Access permissions |
| `-SendAs` | (see note) | Process Send As permissions |
| `-SendOnBehalfOf` | (see note) | Process Send On Behalf Of permissions |
| `-Calendar` | (see note) | Process Calendar folder permissions |
| `-Orphan` | `$false` | Also remove unresolvable SID trustees from all mailboxes |
| `-WhatIf` | — | Simulates all removals; no changes made |
| `-Confirm` | — | Prompts before each removal |
| `-Verbose` | — | Writes detailed progress to the console |

> **Note on permission-type switches:** When none of `-FullAccess`, `-SendAs`, `-SendOnBehalfOf`, or `-Calendar` are specified, all four are processed (backward-compatible default).

### -Orphan behaviour

When `-Orphan` is specified, the script also inspects *every* mailbox (regardless of owner account state) for permission entries whose trustee value is an unresolvable Windows SID (e.g. `S-1-5-21-1234567890-...`). Such entries indicate the original account has been deleted from Active Directory. They are removed automatically and logged with `Reason = "Orphaned SID trustee - <type> cleanup"`.

The `-FullAccess`, `-SendAs`, and `-Calendar` switches still control which permission types are examined for orphans. `-SendOnBehalfOf` is excluded from orphan handling because those entries are stored as Distinguished Names, not SIDs.

```powershell
# Remove only orphaned Full Access and Calendar SID entries (no owner-disabled check)
.\Invoke-MailboxPermissionCleaner.ps1 -Orphan -FullAccess -Calendar -WhatIf
```

---

## CSV Log Columns

`Timestamp`, `MailboxDisplayName`, `MailboxPrimarySmtpAddress`, `MailboxOwnerSamAccountName`, `MailboxOwnerUPN`, `MailboxRecipientType`, `TrusteeOriginal`, `TrusteeResolvedUPN`, `PermissionType`, `RemovedAction`, `Reason`, `Success`, `ErrorMessage`

`RemovedAction` values: `Removed` | `Failed` | `WhatIf`

---

## Architecture

### Caching

Four script-scoped hashtables are populated lazily:

- `$script:TrusteeCache` – raw trustee string → resolved UPN
- `$script:RecipientCache` – identity string → `Get-Recipient` result
- `$script:ADUserCache` – identity string → `Get-ADUser` result
- `$script:CalendarCache` – mailbox identity → calendar folder path

A sentinel value (`__NOT_FOUND__`) is stored for failed lookups so that the same external call is never repeated.

### Localized Calendar Discovery

Exchange stores the calendar folder name in the mailbox language (e.g. `Kalender` in Dutch, `Calendrier` in French). The script uses `Get-MailboxFolderStatistics` and selects the folder where `FolderType -eq 'Calendar'`, then constructs the `<alias>:\<FolderPath>` identifier required by `*-MailboxFolderPermission`.

### Trustee Resolution

Permissions may expose trustees as sAMAccountName, `DOMAIN\sAMAccountName`, Distinguished Name, SID, Alias, or LegacyExchangeDN. `Resolve-Trustee`:

1. Checks the in-memory cache.
2. Calls `Get-Recipient` (handles alias, DN, LegacyExchangeDN, SMTP).
3. Falls back to `Get-ADUser` (SamAccountName or identity).
4. Returns `{ OriginalValue; ResolvedUPN }`.

### -WhatIf / -Confirm

The script declares `[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]`. Every removal is wrapped in `if ($PSCmdlet.ShouldProcess(…))`. With `-WhatIf` the condition is never true, so no changes are made and log entries record `RemovedAction = WhatIf`. With `-Confirm` the user is prompted before each operation.

---

## License

See [LICENSE](LICENSE).
