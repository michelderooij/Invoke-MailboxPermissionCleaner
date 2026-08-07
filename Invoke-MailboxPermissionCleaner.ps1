#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Removes mailbox-related permissions from Exchange mailboxes whose Active Directory
    owner account is disabled, and optionally removes orphaned (SID-only) permissions
    from all mailboxes.

.DESCRIPTION
    Invoke-MailboxPermissionCleaner enumerates all UserMailbox recipients in an Exchange
    on-premises environment.  It operates in two complementary modes:

    Disabled-owner mode (always active)
    ------------------------------------
    For each mailbox whose owner Active Directory account is disabled, it removes the
    permission types selected by the -FullAccess, -SendAs, -SendOnBehalfOf, and
    -Calendar switches.

    Orphan mode (-Orphan switch)
    ----------------------------
    For EVERY mailbox (regardless of owner state), any permission entry whose trustee
    resolves to an unresolvable SID-like value (e.g. "S-1-5-21-...") is treated as an
    orphaned permission – the original account no longer exists in AD or Exchange – and
    is automatically removed.  The -FullAccess, -SendAs, and -Calendar switches still
    gate which permission types are inspected; orphan handling is an additional reason
    to remove, not a separate set of cmdlets.

    When none of -FullAccess, -SendAs, -SendOnBehalfOf, or -Calendar are specified, the
    script behaves as if all four were specified (backward-compatible default).

    The script is designed for production use in large Exchange on-premises environments.
    It uses in-memory hashtable caches so that every AD/Exchange lookup is performed at
    most once per run.  All removal operations are logged to a CSV file and fully support
    -WhatIf and -Confirm.

    Prerequisites
    -------------
    * Must be run from an Exchange Management Shell (EMS) session.
    * The ActiveDirectory PowerShell module must be available.
    * The account running the script requires Exchange Organization Management or
      equivalent permissions to read and remove mailbox permissions.

.PARAMETER LogPath
    Full path to the CSV log file.  If the file already exists it will be appended to.
    Defaults to "MailboxPermissionCleaner_<yyyyMMdd_HHmmss>.csv" in the current directory.

.PARAMETER ResultSize
    Maximum number of mailboxes returned by Get-Mailbox.  Defaults to 'Unlimited'.

.PARAMETER FullAccess
    Process Full Access permissions.  If none of the permission-type switches are
    specified, all four types are processed (default behaviour).

.PARAMETER SendAs
    Process Send As permissions.  See -FullAccess for default behaviour.

.PARAMETER SendOnBehalfOf
    Process Send On Behalf Of permissions.  See -FullAccess for default behaviour.

.PARAMETER Calendar
    Process Calendar folder permissions.  See -FullAccess for default behaviour.

.PARAMETER Orphan
    Additionally remove any permission entry whose trustee cannot be resolved (i.e.
    appears as a raw SID such as "S-1-5-21-...") across ALL mailboxes, regardless of
    whether the mailbox owner's account is disabled.  Combined with the permission-type
    switches to limit which permission types are inspected for orphans.

.PARAMETER WhatIf
    Simulates all removal operations without making changes.  Log entries are still
    written with RemovedAction = "WhatIf".

.PARAMETER Confirm
    Prompts before each removal operation when ConfirmImpact is High.

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1

    Runs against all mailboxes with all permission types (default), logs to a
    timestamped CSV in the current directory.

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1 -WhatIf -Verbose

    Simulates all removals with verbose output.  No changes are made.

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1 -FullAccess -Calendar -Orphan

    Removes Full Access and Calendar permissions from disabled-owner mailboxes AND
    removes orphaned SID entries from those same permission types on all mailboxes.

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1 -Orphan -FullAccess -WhatIf -Verbose

    Simulates orphan Full Access removal across all mailboxes.

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1 -LogPath C:\Logs\cleanup.csv -ResultSize 500

    Processes the first 500 mailboxes and writes the log to C:\Logs\cleanup.csv.

.NOTES
    Author  : Invoke-MailboxPermissionCleaner
    Version : 1.1.0
    Requires: Exchange Management Shell, ActiveDirectory module, PowerShell 5.1+

    Caching Architecture
    --------------------
    Four script-scoped hashtables are populated lazily as lookups are performed:

      $script:TrusteeCache    - Key: raw trustee string  -> resolved UPN or $null
      $script:RecipientCache  - Key: identity string     -> Get-Recipient result
      $script:ADUserCache     - Key: identity string     -> Get-ADUser result
      $script:CalendarCache   - Key: mailbox identity    -> calendar folder path string

    Every external lookup first checks the relevant cache.  A sentinel value
    (__NOT_FOUND__) is stored for failed lookups so that the external call is not
    retried on subsequent occurrences of the same trustee.

    Orphan SID Detection
    --------------------
    A trustee is considered orphaned when:
      1. It matches the SID pattern (^S-1-\d+-\d+(-\d+)+$), OR
      2. It looks like DOMAIN\S-1-... after domain-prefix stripping, OR
      3. All resolution attempts (Get-Recipient, Get-ADUser) fail AND the raw value
         contains only SID-like characters.
    Orphaned entries are removed regardless of the mailbox owner's account state when
    -Orphan is specified.

    Localized Calendar Discovery
    ----------------------------
    Exchange stores the calendar folder name in the mailbox language, so the folder name
    is NOT always "Calendar".  The script uses Get-MailboxFolderStatistics and finds the
    folder whose FolderType property equals "Calendar".  The FolderPath of that entry is
    used to construct the "<alias>:\<FolderPath>" identifier required by the
    *-MailboxFolderPermission cmdlets.

    Trustee Resolution Logic
    ------------------------
    Permissions may expose trustees as sAMAccountName, DOMAIN\sAMAccountName,
    Distinguished Name, SID, Alias, or LegacyExchangeDN.  The Resolve-Trustee function:

      1. Checks the in-memory cache first.
      2. Calls Get-Recipient -Identity <trustee> (handles alias, DN, LegacyExchangeDN,
         SMTP address).
      3. Falls back to Get-ADUser with a -Filter on SamAccountName, DistinguishedName,
         SID, or UserPrincipalName.
      4. Returns a PSCustomObject with OriginalValue, ResolvedUPN, and IsOrphanSid
         properties.
      5. Stores the result (or sentinel) in the cache.

    WhatIf / Confirm Implementation
    --------------------------------
    The script declares [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')].
    Every call to Remove-MailboxPermission, Remove-ADPermission, Set-Mailbox, and
    Remove-MailboxFolderPermission is guarded by an explicit
      if ($PSCmdlet.ShouldProcess(...)) { ... }
    check so that -WhatIf suppresses all changes and -Confirm prompts before each one.
    Log entries written during a -WhatIf run set RemovedAction = "WhatIf".
#>

[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact         = 'High'
)]
param (
    [Parameter()]
    [string]$LogPath = (Join-Path -Path (Get-Location) -ChildPath ("MailboxPermissionCleaner_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),

    [Parameter()]
    [string]$ResultSize = 'Unlimited',

    [Parameter()]
    [switch]$FullAccess,

    [Parameter()]
    [switch]$SendAs,

    [Parameter()]
    [switch]$SendOnBehalfOf,

    [Parameter()]
    [switch]$Calendar,

    [Parameter()]
    [switch]$Orphan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Promote LogPath to script scope so that Write-LogEntry (a nested function) can access it
$script:LogPath = $LogPath
$anyTypeSwitch = $FullAccess -or $SendAs -or $SendOnBehalfOf -or $Calendar
if (-not $anyTypeSwitch) {
    $FullAccess      = $true
    $SendAs          = $true
    $SendOnBehalfOf  = $true
    $Calendar        = $true
}

#region --- Cache initialisation ---------------------------------------------------

$script:TrusteeCache   = @{}   # raw trustee string  -> UPN string | $null
$script:RecipientCache = @{}   # identity string     -> recipient object | $null
$script:ADUserCache    = @{}   # identity string     -> ADUser object    | $null
$script:CalendarCache  = @{}   # mailbox identity    -> calendar folder path string

$script:SENTINEL = '__NOT_FOUND__'

#endregion

#region --- Logging ----------------------------------------------------------------

function Write-LogEntry {
    <#
    .SYNOPSIS
        Appends one row to the CSV log file and optionally writes to Verbose.
    .PARAMETER Entry
        A hashtable whose keys match the CSV column names.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Entry
    )

    $row = [PSCustomObject][ordered]@{
        Timestamp                  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        MailboxDisplayName         = $Entry['MailboxDisplayName']
        MailboxPrimarySmtpAddress  = $Entry['MailboxPrimarySmtpAddress']
        MailboxOwnerSamAccountName = $Entry['MailboxOwnerSamAccountName']
        MailboxOwnerUPN            = $Entry['MailboxOwnerUPN']
        MailboxRecipientType       = $Entry['MailboxRecipientType']
        TrusteeOriginal            = $Entry['TrusteeOriginal']
        TrusteeResolvedUPN         = $Entry['TrusteeResolvedUPN']
        PermissionType             = $Entry['PermissionType']
        RemovedAction              = $Entry['RemovedAction']
        Reason                     = $Entry['Reason']
        Success                    = $Entry['Success']
        ErrorMessage               = $Entry['ErrorMessage']
    }

    $row | Export-Csv -Path $script:LogPath -Append -NoTypeInformation -Encoding UTF8

    $verboseMsg = "[{0}] Mailbox={1} | Permission={2} | Trustee={3} | Action={4} | Success={5}" -f $row.Timestamp, $row.MailboxDisplayName, $row.PermissionType, $row.TrusteeOriginal, $row.RemovedAction, $row.Success
    Write-Verbose $verboseMsg
}

#endregion

#region --- Trustee resolution -----------------------------------------------------

function Test-IsOrphanSid {
    <#
    .SYNOPSIS
        Returns $true when the supplied string looks like an unresolvable SID.
    .DESCRIPTION
        A trustee that Exchange cannot map to an object is often displayed as a raw
        Windows SID (e.g. S-1-5-21-1234567890-0987654321-111111111-1234).  These
        "orphan" entries can be safely removed because the underlying account no
        longer exists.
    .PARAMETER Value
        The trustee string to test.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string]$Value
    )

    # Strip DOMAIN\ prefix if present
    $test = $Value
    if ($Value -match '^[^\\]+\\(.+)$') {
        $test = $Matches[1]
    }

    return $test -match '^S-1-\d+-\d+(-\d+)+$'
}

function Resolve-Trustee {
    <#
    .SYNOPSIS
        Resolves a trustee identity to a User Principal Name.
    .DESCRIPTION
        Checks the in-memory cache first.  Attempts Get-Recipient, then Get-ADUser.
        Returns a PSCustomObject with OriginalValue, ResolvedUPN, and IsOrphanSid.
        IsOrphanSid is $true when the trustee value is a raw SID that could not be
        resolved to any known object.
    .PARAMETER Trustee
        The raw trustee string as returned by a permission cmdlet.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$Trustee
    )

    $result = [PSCustomObject]@{
        OriginalValue = $Trustee
        ResolvedUPN   = $null
        IsOrphanSid   = $false
    }

    if ($script:TrusteeCache.ContainsKey($Trustee)) {
        $cached = $script:TrusteeCache[$Trustee]
        $result.ResolvedUPN = if ($cached -eq $script:SENTINEL) { $null } else { $cached }
        $result.IsOrphanSid = ($cached -eq $script:SENTINEL) -and (Test-IsOrphanSid -Value $Trustee)
        return $result
    }

    # Strip DOMAIN\ prefix to get sAMAccountName for Exchange lookups
    $identity = $Trustee
    if ($Trustee -match '^[^\\]+\\(.+)$') {
        $identity = $Matches[1]
    }

    # --- Attempt 1: Get-Recipient ---
    $recipient = $null
    if ($script:RecipientCache.ContainsKey($identity)) {
        $recipient = $script:RecipientCache[$identity]
        if ($recipient -eq $script:SENTINEL) { $recipient = $null }
    }
    else {
        try {
            $recipient = Get-Recipient -Identity $identity -ErrorAction Stop |
                         Select-Object -First 1
            $script:RecipientCache[$identity] = $recipient
        }
        catch {
            $script:RecipientCache[$identity] = $script:SENTINEL
            $recipient = $null
        }
    }

    if ($recipient -and $recipient.PrimarySmtpAddress) {
        $upn = $recipient.PrimarySmtpAddress.ToString()
        $script:TrusteeCache[$Trustee] = $upn
        $result.ResolvedUPN = $upn
        return $result
    }

    # --- Attempt 2: Get-ADUser ---
    $adUser = $null
    if ($script:ADUserCache.ContainsKey($identity)) {
        $adUser = $script:ADUserCache[$identity]
        if ($adUser -eq $script:SENTINEL) { $adUser = $null }
    }
    else {
        try {
            # Try SamAccountName first, then SID, then DN
            $adUser = Get-ADUser -Filter { SamAccountName -eq $identity } -Properties UserPrincipalName -ErrorAction Stop |
                Select-Object -First 1

            if (-not $adUser) {
                $adUser = Get-ADUser -Identity $identity -Properties UserPrincipalName -ErrorAction Stop
            }
            $script:ADUserCache[$identity] = $adUser
        }
        catch {
            $script:ADUserCache[$identity] = $script:SENTINEL
            $adUser = $null
        }
    }

    if ($adUser -and $adUser.UserPrincipalName) {
        $upn = $adUser.UserPrincipalName
        $script:TrusteeCache[$Trustee] = $upn
        $result.ResolvedUPN = $upn
        return $result
    }

    # Unresolved – mark as orphan if value looks like a SID
    $script:TrusteeCache[$Trustee] = $script:SENTINEL
    $result.IsOrphanSid = Test-IsOrphanSid -Value $Trustee
    return $result
}

#endregion

#region --- Calendar folder discovery ---------------------------------------------

function Get-CalendarFolderPath {
    <#
    .SYNOPSIS
        Returns the "<alias>:\<FolderPath>" string for a mailbox's Calendar folder,
        regardless of display language.
    .PARAMETER MailboxIdentity
        The Identity parameter value for the target mailbox.
    .PARAMETER MailboxAlias
        The Alias of the mailbox (used to build the folder identifier).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [string]$MailboxIdentity,

        [Parameter(Mandatory)]
        [string]$MailboxAlias
    )

    if ($script:CalendarCache.ContainsKey($MailboxIdentity)) {
        return $script:CalendarCache[$MailboxIdentity]
    }

    try {
        $calFolder = Get-MailboxFolderStatistics -Identity $MailboxIdentity -ErrorAction Stop |
            Where-Object { $_.FolderType -eq 'Calendar' } |
            Select-Object -First 1

        if ($calFolder) {
            # FolderPath is like "/Calendar" or "/Kalender" etc.
            # Build the identifier required by *-MailboxFolderPermission
            $folderPath = $calFolder.FolderPath.TrimStart('/')
            $identifier = '{0}:\{1}' -f $MailboxAlias, $folderPath
            $script:CalendarCache[$MailboxIdentity] = $identifier
            return $identifier
        }
    }
    catch {
        Write-Warning ("Could not retrieve folder statistics for '{0}': {1}" -f $MailboxIdentity, $_.Exception.Message)
    }

    $script:CalendarCache[$MailboxIdentity] = $null
    return $null
}

#endregion

#region --- Mailbox owner lookup --------------------------------------------------

function Get-MailboxOwnerADUser {
    <#
    .SYNOPSIS
        Returns the ADUser object for a mailbox owner, using a cache.
    .PARAMETER SamAccountName
        The sAMAccountName of the mailbox owner.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory)]
        [string]$SamAccountName
    )

    if ($script:ADUserCache.ContainsKey($SamAccountName)) {
        $cached = $script:ADUserCache[$SamAccountName]
        if ($cached -eq $script:SENTINEL) {
            return $null
        }
        return $cached
    }

    try {
        $adUser = Get-ADUser -Identity $SamAccountName -Properties Enabled, UserPrincipalName -ErrorAction Stop
        $script:ADUserCache[$SamAccountName] = $adUser
        return $adUser
    }
    catch {
        Write-Verbose ("Get-ADUser failed for '{0}': {1}" -f $SamAccountName, $_.Exception.Message)
        $script:ADUserCache[$SamAccountName] = $script:SENTINEL
        return $null
    }
}

#endregion

#region --- Permission removal helpers -------------------------------------------

function Remove-FullAccessPermissions {
    <#
    .SYNOPSIS
        Removes Full Access permissions from a mailbox, skipping inherited/deny/SELF entries.
    .DESCRIPTION
        Removes entries whose owner is disabled.  When -IncludeOrphan is set, also removes
        entries whose trustee is an unresolvable SID regardless of owner state.
    .PARAMETER Mailbox
        The mailbox object returned by Get-Mailbox.
    .PARAMETER BaseEntry
        A hashtable of common log fields already populated for this mailbox.
    .PARAMETER OwnerIsDisabled
        When $true the function removes permissions because the mailbox owner is disabled.
    .PARAMETER IncludeOrphan
        When $true the function also removes orphaned SID trustees.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [object]$Mailbox,

        [Parameter(Mandatory)]
        [hashtable]$BaseEntry,

        [Parameter()]
        [bool]$OwnerIsDisabled = $false,

        [Parameter()]
        [bool]$IncludeOrphan = $false
    )

    if (-not $OwnerIsDisabled -and -not $IncludeOrphan) { return }

    Write-Verbose ("  Processing Full Access for: {0}" -f $Mailbox.PrimarySmtpAddress)

    try {
        $permissions = Get-MailboxPermission -Identity $Mailbox.Identity -ErrorAction Stop |
            Where-Object {
                $_.IsInherited -eq $false -and
                $_.Deny       -eq $false -and
                $_.User -notmatch 'NT AUTHORITY\\SELF'
            }
    }
    catch {
        Write-Warning ("Get-MailboxPermission failed for '{0}': {1}" -f $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
        return
    }

    foreach ($perm in $permissions) {
        $trusteeRaw = $perm.User.ToString()
        $resolved   = Resolve-Trustee -Trustee $trusteeRaw

        $shouldRemove = $OwnerIsDisabled -or ($IncludeOrphan -and $resolved.IsOrphanSid)
        if (-not $shouldRemove) { continue }

        $reason = if ($resolved.IsOrphanSid -and -not $OwnerIsDisabled) {
            'Orphaned SID trustee - Full Access cleanup'
        }
        else {
            'Disabled mailbox owner account - Full Access cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal']    = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType']     = 'FullAccess'
        $entry['Reason']             = $reason

        $spDescription = "Remove Full Access for '{0}' on mailbox '{1}'" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress

        if ($PSCmdlet.ShouldProcess($spDescription, 'Remove-MailboxPermission')) {
            try {
                Remove-MailboxPermission -Identity $Mailbox.Identity -User $trusteeRaw -AccessRights FullAccess -Confirm:$false -ErrorAction Stop
                $entry['RemovedAction'] = 'Removed'
                $entry['Success']       = $true
                $entry['ErrorMessage']  = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success']       = $false
                $entry['ErrorMessage']  = $_.Exception.Message
                Write-Warning ("Failed to remove Full Access for '{0}' on '{1}': {2}" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success']       = $true
            $entry['ErrorMessage']  = ''
        }

        Write-LogEntry -Entry $entry
    }
}

function Remove-SendAsPermissions {
    <#
    .SYNOPSIS
        Removes Send As permissions from a mailbox using Get-ADPermission.
    .DESCRIPTION
        Removes entries whose owner is disabled.  When -IncludeOrphan is set, also removes
        entries whose trustee is an unresolvable SID regardless of owner state.
    .PARAMETER Mailbox
        The mailbox object returned by Get-Mailbox.
    .PARAMETER BaseEntry
        A hashtable of common log fields already populated for this mailbox.
    .PARAMETER OwnerIsDisabled
        When $true the function removes permissions because the mailbox owner is disabled.
    .PARAMETER IncludeOrphan
        When $true the function also removes orphaned SID trustees.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [object]$Mailbox,

        [Parameter(Mandatory)]
        [hashtable]$BaseEntry,

        [Parameter()]
        [bool]$OwnerIsDisabled = $false,

        [Parameter()]
        [bool]$IncludeOrphan = $false
    )

    if (-not $OwnerIsDisabled -and -not $IncludeOrphan) { return }

    Write-Verbose ("  Processing Send As for: {0}" -f $Mailbox.PrimarySmtpAddress)

    try {
        $adPerms = Get-ADPermission -Identity $Mailbox.Identity -ErrorAction Stop |
            Where-Object {
                $_.ExtendedRights -match 'Send-As' -and
                $_.IsInherited -eq $false -and
                $_.Deny        -eq $false
            }
    }
    catch {
        Write-Warning ("Get-ADPermission failed for '{0}': {1}" -f $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
        return
    }

    foreach ($perm in $adPerms) {
        $trusteeRaw = $perm.User.ToString()
        $resolved   = Resolve-Trustee -Trustee $trusteeRaw

        $shouldRemove = $OwnerIsDisabled -or ($IncludeOrphan -and $resolved.IsOrphanSid)
        if (-not $shouldRemove) { continue }

        $reason = if ($resolved.IsOrphanSid -and -not $OwnerIsDisabled) {
            'Orphaned SID trustee - Send As cleanup'
        }
        else {
            'Disabled mailbox owner account - Send As cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal']    = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType']     = 'SendAs'
        $entry['Reason']             = $reason

        $spDescription = "Remove Send As for '{0}' on mailbox '{1}'" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress

        if ($PSCmdlet.ShouldProcess($spDescription, 'Remove-ADPermission')) {
            try {
                Remove-ADPermission -Identity $Mailbox.Identity -User $trusteeRaw -ExtendedRights 'Send-As' -Confirm:$false -ErrorAction Stop
                $entry['RemovedAction'] = 'Removed'
                $entry['Success']       = $true
                $entry['ErrorMessage']  = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success']       = $false
                $entry['ErrorMessage']  = $_.Exception.Message
                Write-Warning ("Failed to remove Send As for '{0}' on '{1}': {2}" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success']       = $true
            $entry['ErrorMessage']  = ''
        }

        Write-LogEntry -Entry $entry
    }
}

function Remove-SendOnBehalfPermissions {
    <#
    .SYNOPSIS
        Clears all Send On Behalf delegates from a mailbox.
    .DESCRIPTION
        Send On Behalf entries are stored as Distinguished Names so orphan-SID detection
        is not applicable here; this function only runs when the mailbox owner is disabled.
    .PARAMETER Mailbox
        The mailbox object returned by Get-Mailbox.
    .PARAMETER BaseEntry
        A hashtable of common log fields already populated for this mailbox.
    .PARAMETER OwnerIsDisabled
        When $true the function removes permissions because the mailbox owner is disabled.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [object]$Mailbox,

        [Parameter(Mandatory)]
        [hashtable]$BaseEntry,

        [Parameter()]
        [bool]$OwnerIsDisabled = $false
    )

    if (-not $OwnerIsDisabled) { return }

    Write-Verbose ("  Processing Send On Behalf for: {0}" -f $Mailbox.PrimarySmtpAddress)

    $delegates = $Mailbox.GrantSendOnBehalfTo
    if (-not $delegates -or $delegates.Count -eq 0) {
        Write-Verbose ("    No Send On Behalf delegates found.")
        return
    }

    foreach ($delegate in $delegates) {
        $trusteeRaw = $delegate.ToString()
        $resolved   = Resolve-Trustee -Trustee $trusteeRaw

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal']    = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType']     = 'SendOnBehalf'
        $entry['Reason']             = 'Disabled mailbox owner account - Send On Behalf cleanup'

        $spDescription = "Remove Send On Behalf delegate '{0}' from mailbox '{1}'" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress

        if ($PSCmdlet.ShouldProcess($spDescription, 'Set-Mailbox')) {
            try {
                Set-Mailbox -Identity $Mailbox.Identity -GrantSendOnBehalfTo @{ Remove = $trusteeRaw } -Confirm:$false -ErrorAction Stop
                $entry['RemovedAction'] = 'Removed'
                $entry['Success']       = $true
                $entry['ErrorMessage']  = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success']       = $false
                $entry['ErrorMessage']  = $_.Exception.Message
                Write-Warning ("Failed to remove Send On Behalf for '{0}' on '{1}': {2}" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success']       = $true
            $entry['ErrorMessage']  = ''
        }

        Write-LogEntry -Entry $entry
    }
}

function Remove-CalendarPermissions {
    <#
    .SYNOPSIS
        Removes non-Default, non-Anonymous calendar permissions from a mailbox.
    .DESCRIPTION
        Removes entries whose owner is disabled.  When -IncludeOrphan is set, also removes
        entries whose trustee is an unresolvable SID regardless of owner state.
    .PARAMETER Mailbox
        The mailbox object returned by Get-Mailbox.
    .PARAMETER BaseEntry
        A hashtable of common log fields already populated for this mailbox.
    .PARAMETER OwnerIsDisabled
        When $true the function removes permissions because the mailbox owner is disabled.
    .PARAMETER IncludeOrphan
        When $true the function also removes orphaned SID trustees.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [object]$Mailbox,

        [Parameter(Mandatory)]
        [hashtable]$BaseEntry,

        [Parameter()]
        [bool]$OwnerIsDisabled = $false,

        [Parameter()]
        [bool]$IncludeOrphan = $false
    )

    if (-not $OwnerIsDisabled -and -not $IncludeOrphan) { return }

    Write-Verbose ("  Processing Calendar permissions for: {0}" -f $Mailbox.PrimarySmtpAddress)

    $calPath = Get-CalendarFolderPath -MailboxIdentity $Mailbox.Identity -MailboxAlias $Mailbox.Alias

    if (-not $calPath) {
        Write-Warning ("Could not determine calendar folder path for '{0}'. Skipping." -f $Mailbox.PrimarySmtpAddress)
        return
    }

    Write-Verbose ("    Calendar folder path: {0}" -f $calPath)

    try {
        $calPerms = Get-MailboxFolderPermission -Identity $calPath -ErrorAction Stop |
            Where-Object {
                $_.User.DisplayName -ne 'Default' -and
                $_.User.DisplayName -ne 'Anonymous'
            }
    }
    catch {
        Write-Warning ("Get-MailboxFolderPermission failed for '{0}': {1}" -f $calPath, $_.Exception.Message)
        return
    }

    foreach ($perm in $calPerms) {
        $trusteeRaw = $perm.User.ToString()
        $resolved   = Resolve-Trustee -Trustee $trusteeRaw

        $shouldRemove = $OwnerIsDisabled -or ($IncludeOrphan -and $resolved.IsOrphanSid)
        if (-not $shouldRemove) { continue }

        $reason = if ($resolved.IsOrphanSid -and -not $OwnerIsDisabled) {
            'Orphaned SID trustee - Calendar permission cleanup'
        }
        else {
            'Disabled mailbox owner account - Calendar permission cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal']    = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType']     = 'CalendarPermission'
        $entry['Reason']             = $reason

        $spDescription = "Remove Calendar permission for '{0}' on '{1}'" -f $trusteeRaw, $calPath

        if ($PSCmdlet.ShouldProcess($spDescription, 'Remove-MailboxFolderPermission')) {
            try {
                Remove-MailboxFolderPermission -Identity $calPath -User $trusteeRaw -Confirm:$false -ErrorAction Stop
                $entry['RemovedAction'] = 'Removed'
                $entry['Success']       = $true
                $entry['ErrorMessage']  = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success']       = $false
                $entry['ErrorMessage']  = $_.Exception.Message
                Write-Warning ("Failed to remove Calendar permission for '{0}' on '{1}': {2}" -f $trusteeRaw, $calPath, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success']       = $true
            $entry['ErrorMessage']  = ''
        }

        Write-LogEntry -Entry $entry
    }
}

#endregion

#region --- Main script body -----------------------------------------------------

Write-Verbose ("Log file: {0}" -f $LogPath)
Write-Verbose "Retrieving mailboxes..."

try {
    $allMailboxes = @(Get-Mailbox -ResultSize $ResultSize -RecipientTypeDetails UserMailbox -ErrorAction Stop)
}
catch {
    throw ("Failed to retrieve mailboxes: {0}" -f $_.Exception.Message)
}

$total   = $allMailboxes.Count
$current = 0

Write-Verbose ("Found {0} UserMailbox recipients." -f $total)

foreach ($mbx in $allMailboxes) {
    $current++
    Write-Progress -Activity 'Invoke-MailboxPermissionCleaner' -Status ("Processing {0} of {1}: {2}" -f $current, $total, $mbx.PrimarySmtpAddress) -PercentComplete (($current / $total) * 100)

    Write-Verbose ("[{0}/{1}] Checking: {2}" -f $current, $total, $mbx.PrimarySmtpAddress)

    # --- Determine if the mailbox owner AD account is disabled ---
    $ownerSam      = $mbx.SamAccountName
    $ownerDisabled = $false
    $adUser        = $null

    if ([string]::IsNullOrWhiteSpace($ownerSam)) {
        Write-Verbose ("  No SamAccountName found.")
    }
    else {
        $adUser = Get-MailboxOwnerADUser -SamAccountName $ownerSam
        if (-not $adUser) {
            Write-Verbose ("  Could not retrieve AD account for '{0}'." -f $ownerSam)
        }
        elseif ($adUser.Enabled -eq $false) {
            $ownerDisabled = $true
            Write-Verbose ("  Account '{0}' is DISABLED." -f $ownerSam)
        }
        else {
            Write-Verbose ("  Account '{0}' is enabled." -f $ownerSam)
        }
    }

    # Skip entirely when neither condition warrants processing
    if (-not $ownerDisabled -and -not $Orphan) {
        continue
    }

    # Build the base log entry shared by all permission removals for this mailbox
    $baseEntry = @{
        MailboxDisplayName         = $mbx.DisplayName
        MailboxPrimarySmtpAddress  = $mbx.PrimarySmtpAddress.ToString()
        MailboxOwnerSamAccountName = if ($ownerSam) { $ownerSam } else { '' }
        MailboxOwnerUPN            = if ($adUser -and $adUser.UserPrincipalName) { $adUser.UserPrincipalName } else { '' }
        MailboxRecipientType       = $mbx.RecipientTypeDetails.ToString()
        TrusteeOriginal            = ''
        TrusteeResolvedUPN         = ''
        PermissionType             = ''
        RemovedAction              = ''
        Reason                     = 'Disabled mailbox owner account'
        Success                    = $true
        ErrorMessage               = ''
    }

    if ($FullAccess) {
        try {
            Remove-FullAccessPermissions -Mailbox $mbx -BaseEntry $baseEntry -OwnerIsDisabled $ownerDisabled -IncludeOrphan ([bool]$Orphan)
        }
        catch {
            Write-Warning ("Unexpected error in Remove-FullAccessPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }

    if ($SendAs) {
        try {
            Remove-SendAsPermissions -Mailbox $mbx -BaseEntry $baseEntry -OwnerIsDisabled $ownerDisabled -IncludeOrphan ([bool]$Orphan)
        }
        catch {
            Write-Warning ("Unexpected error in Remove-SendAsPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }

    if ($SendOnBehalfOf) {
        try {
            Remove-SendOnBehalfPermissions -Mailbox $mbx -BaseEntry $baseEntry -OwnerIsDisabled $ownerDisabled
        }
        catch {
            Write-Warning ("Unexpected error in Remove-SendOnBehalfPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }

    if ($Calendar) {
        try {
            Remove-CalendarPermissions -Mailbox $mbx -BaseEntry $baseEntry -OwnerIsDisabled $ownerDisabled -IncludeOrphan ([bool]$Orphan)
        }
        catch {
            Write-Warning ("Unexpected error in Remove-CalendarPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }
}

Write-Progress -Activity 'Invoke-MailboxPermissionCleaner' -Completed
Write-Verbose ("Processing complete. Log written to: {0}" -f $LogPath)

#endregion
