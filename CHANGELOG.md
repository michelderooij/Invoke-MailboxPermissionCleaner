# Changelog

All notable changes to `Invoke-MailboxPermissionCleaner` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.6.4] - 2026-08-11

### Added

- Added `-IgnoreDisabledOwner` switch to ignore mailbox owner disabled-state as a removal trigger.
- Added `TrusteeRecipientTypeDetails` column to output/log rows when trustee recipient type can be resolved.
- Added `MailboxOwnerOU` column to output/log rows, populated from owner distinguished name OU components when available.

### Changed

- Renamed output/log column `TrusteeResolvedUPN` to `TrusteeResolvedIdentity` to reflect that resolved values can be DistinguishedName, SMTP, or UPN.

## [1.6.3] - 2026-08-11

### Changed

- `-WhatIf` runs now write findings to both the pipeline and the CSV log file (`-LogPath`) for auditability.

## [1.6.2] - 2026-08-11

### Changed

- Implemented batched CSV logging writes to reduce per-entry I/O overhead.
- Switched mailbox processing to streaming enumeration instead of preloading all mailboxes in memory.
- Hardened EXO disabled-state checks with explicit warnings when disabled state cannot be determined.
- Corrected AD trustee lookup filter construction for SamAccountName resolution.

## [1.6.1] - 2026-08-11

### Changed

- Removed user-facing `-Environment` parameter.
- Environment selection is now always automatic at startup (on-premises vs Exchange Online).

## [1.6.0] - 2026-08-11

### Added

- **Unified environment support** in one script via new `-Environment` parameter with values `Auto`, `OnPrem`, and `ExchangeOnline`.
- **Automatic environment detection** at startup, with validation of required cmdlets for the resolved mode.
- **Exchange Online Send As routing** using `Get-RecipientPermission` and `Remove-RecipientPermission`.

### Changed

- Removed hard `#Requires -Modules ActiveDirectory` dependency so Exchange Online mode can run without the AD module.
- `-Orphan` is now **on-premises only**; in Exchange Online mode the script writes a notice and continues with orphan handling disabled.
- Owner/trustee disabled-account checks are now environment-aware:
  - On-premises: `Get-ADUser`
  - Exchange Online: `Get-User` (without Graph dependency)

### Documentation

- Updated script help and README to describe unified on-premises/Exchange Online behavior, Send As cmdlet routing, and the on-premises-only orphan limitation.

## [1.5.1] - 2026-08-07

### Added

- **Automatic multi-forest detection** — at startup the script calls `Get-ADForest` and, when the forest contains more than one domain, automatically calls `Set-ADServerSettings -ViewEntireForest $true`. This ensures Exchange AD lookups span all domains in linked-mailbox/resource-forest topologies without any manual switch.
- **`-Orphan` switch** — additionally removes permission entries whose trustee is an unresolvable Windows SID (e.g., `S-1-5-21-...`) from every mailbox, regardless of owner account state.
- **Disabled trustee detection** — the script now checks each permission's trustee (delegate) to determine if that account is disabled in Active Directory. If a trustee is disabled, the permission is removed regardless of the mailbox owner's state. This works across all permission types: Full Access, Send As, Send On Behalf, and Calendar.
- `Test-TrusteeIsDisabled` helper function to query AD for trustee account status, with dedicated caching (`$script:TrusteeDisabledCache`) to avoid redundant lookups and verbose diagnostic output showing AD lookup results.
- `Test-IsOrphanSid` helper function for reliable SID-pattern detection, including `DOMAIN\S-1-...` variants, with `IsOrphanSid` property on the object returned by `Resolve-Trustee`.
- **User-only filtering** — when evaluating trustee disabled state, only user accounts are queried (via `Get-ADUser`). Group-based permissions are automatically excluded from disabled-trustee evaluation, ensuring that group delegations are preserved.
- Comprehensive diagnostic verbose output to all permission removal functions showing permission count, resolution details, and removal decision logic, making troubleshooting much easier.

### Fixed

- **Critical bugfix**: `Resolve-Trustee` was returning `PrimarySmtpAddress` (email address) instead of `DistinguishedName` when resolving trustees via `Get-Recipient`. This caused `Test-TrusteeIsDisabled` to fail silently when looking up the trustee in Active Directory, since `Get-ADUser -Identity` does not accept SMTP addresses (only UPN, SamAccountName, DistinguishedName, GUID, or SID). Now `Resolve-Trustee` prioritizes `DistinguishedName` from the Recipient object, with fallback to `PrimarySmtpAddress` only if DN is unavailable.

- **Mailbox processing bugfix**: The script was skipping all mailboxes with **enabled owners** unless orphan mode was active, which prevented detection of disabled-trustee permissions on enabled-owner mailboxes. Now **all mailboxes are always checked for disabled trustees** regardless of owner state.

- **Format normalization bugfix**: `Resolve-Trustee` now handles multiple trustee formats correctly:
  - `DOMAIN\sAMAccountName` (e.g., `AD\testuser`) → extracts `testuser`
  - Slash-separated DN (e.g., `ad.myexchangelabs.com/NL/testuser`) → extracts last component
  - Bare sAMAccountName (e.g., `testuser`) → uses as-is
  - DN, SID, GUID → uses as-is

  This ensures trustees from different permission types (Full Access, Send As, Calendar, Send On Behalf) are correctly resolved regardless of format.

- **Send As regex bugfix**: Changed pattern from `'Send-As'` to `'SendAs|Send-As'` to match both hyphenated and non-hyphenated variants.

- **Implicit remoting bugfix**: All four removal functions now resolve mailbox identity to a plain SMTP address string before passing it to Exchange cmdlets. Objects returned by `Get-Mailbox` are `Deserialized.*` types and cannot be passed back to Exchange cmdlets as `-Identity` without first converting to strings.

- **Collection count bugfix**: Fixed `.Count` property handling to use `@($collection).Count` for safe evaluation of single vs. multiple objects, preventing "property 'Count' cannot be found" errors.

### Changed

- Removal logic in all four permission functions now checks **both** mailbox owner state and trustee state; a permission is removed if either is disabled.
- `$script:TrusteeDisabledCache` caches disabled state lookups by resolved UPN to prevent repeated AD queries.
- NT AUTHORITY\SELF permissions are now skipped when processing Send As and Send On Behalf permissions.
- Calendar folder permissions now skip entries with DisplayName = 'Default', 'Anonymous', and 'SELF'.
- `-SendOnBehalfOf` is explicitly excluded from orphan handling (delegates are stored as DNs, not SIDs).
- When none of `-FullAccess`, `-SendAs`, `-SendOnBehalfOf`, or `-Calendar` are specified, all four are now activated automatically (backward-compatible default).
- Updated CSV log `Reason` values to distinguish between "Disabled mailbox owner account" and "Disabled trustee" scenarios.

### Removed

- **`-ReportOnly` switch** — consolidated with `-WhatIf`. When `-WhatIf` is specified, findings are emitted to the pipeline instead of being written to the CSV log file.
- **`-ViewEntireForest` switch** — replaced by automatic multi-forest detection.
