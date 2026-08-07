<#
    .SYNOPSIS
    Invoke-MailboxPermissionCleaner
    Removes mailbox-related permissions from Exchange mailboxes whose Active Directory
    owner account is disabled, and optionally removes orphaned (SID-only) permissions
    from all mailboxes.

    Michel de Rooij
    michel@eightwone.com

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE
    ENTIRE RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS
    WITH THE USER.

    Version 1.31, August 7, 2026

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

    Linked Mailbox / Multi-Forest Support
    --------------------------------------
    In environments with linked mailboxes, the mailbox exists in a dedicated Exchange
    resource forest while the owner account lives in a separate accounts forest.  In
    this topology, Exchange cmdlets that rely on the AD topology service (Get-Recipient,
    Get-ADPermission, Remove-ADPermission) may only see the local forest by default.
    When the script detects that the Active Directory forest contains more than one
    domain, it automatically calls Set-ADServerSettings -ViewEntireForest $true so
    that all Exchange AD lookups span the entire forest.

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
    Simulates all removal operations without making changes.  Findings are written to
    the pipeline instead of the log file and can be piped to Out-GridView or Export-Csv.

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

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1 -WhatIf | Out-GridView

    Scans all mailboxes and displays every finding in a grid view without making
    any changes or writing a log file.

.EXAMPLE
    .\Invoke-MailboxPermissionCleaner.ps1 -WhatIf -Orphan -FullAccess | Export-Csv -Path C:\Reports\findings.csv -NoTypeInformation

    Reports orphaned Full Access entries across all mailboxes and exports the
    results to a CSV without making any changes.

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
    When -WhatIf is specified, findings are written to the pipeline instead of the log
    file; the results can be captured, piped to Out-GridView, or exported to CSV.
#>
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = 'High'
)]
param (
    [Parameter()]
    [string]$LogPath = (Join-Path -Path (Get-Location) -ChildPath ("Invoke-MailboxPermissionCleaner-{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),

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
    $FullAccess = $true
    $SendAs = $true
    $SendOnBehalfOf = $true
    $Calendar = $true
}

#region --- Cache initialisation ---------------------------------------------------

$script:TrusteeCache = @{}   # raw trustee string  -> UPN string | $null
$script:RecipientCache = @{}   # identity string     -> recipient object | $null
$script:ADUserCache = @{}   # identity string     -> ADUser object    | $null
$script:CalendarCache = @{}   # mailbox identity    -> calendar folder path string
$script:TrusteeDisabledCache = @{}   # resolved UPN -> $true (disabled) | $false (enabled) | $SENTINEL (not a user)

$script:SENTINEL = '__NOT_FOUND__'
$script:LogEntryCount = 0

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

    $script:LogEntryCount++

    if ($WhatIfPreference) {
        Write-Output $row
    }
    else {
        try {
            $row | Export-Csv -Path $script:LogPath -Append -NoTypeInformation -Encoding UTF8
        }
        catch {
            Write-Warning ("Failed to write log entry to '{0}': {1}" -f $script:LogPath, $_.Exception.Message)
        }
    }

    $verboseArgs = @(
        $row.Timestamp
        $row.MailboxDisplayName
        $row.PermissionType
        $row.TrusteeOriginal
        $row.RemovedAction
        $row.Success
    )
    $verboseMsg = "[{0}] Mailbox={1} | Permission={2} | Trustee={3} | Action={4} | Success={5}" -f $verboseArgs
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
        Write-Verbose ("      [Resolve-Trustee] Cache hit for '{0}': ResolvedUPN={1}, IsOrphanSid={2}" -f $Trustee, $(if ($result.ResolvedUPN) { $result.ResolvedUPN } else { 'NULL' }), $result.IsOrphanSid)
        return $result
    }

    Write-Verbose ("      [Resolve-Trustee] Cache miss for '{0}' - attempting resolution" -f $Trustee)

    # Normalize various identity formats to a common lookup format
    $identity = $Trustee

    # Handle slash-separated DN format (e.g., "ad.myexchangelabs.com/NL/testuser")
    # Extract the last component as sAMAccountName
    if ($Trustee -match '/') {
        $parts = $Trustee -split '/'
        $identity = $parts[-1]  # Get the last component
    }
    # Handle domain\sAMAccountName format (e.g., "AD\testuser")
    elseif ($Trustee -match '^[^\\]+\\(.+)$') {
        $identity = $Matches[1]
    }
    # Otherwise assume it's already a sAMAccountName or DN

    # Check normalized identity in cache — different original formats (AD\user, domain/OU/user, user)
    # all normalize to the same sAMAccountName. If we already resolved it under a previous call,
    # reuse that result to guarantee the same DN string (avoiding deserialization inconsistencies
    # where two Get-Recipient calls return visually identical but subtly different DN objects).
    if ($identity -ne $Trustee -and $script:TrusteeCache.ContainsKey($identity)) {
        $cached = $script:TrusteeCache[$identity]
        $script:TrusteeCache[$Trustee] = $cached  # also store under original key
        $result.ResolvedUPN = if ($cached -eq $script:SENTINEL) { $null } else { $cached }
        $result.IsOrphanSid = ($cached -eq $script:SENTINEL) -and (Test-IsOrphanSid -Value $Trustee)
        Write-Verbose ("      [Resolve-Trustee] Cache hit (via normalized '{0}') for '{1}': ResolvedUPN={2}" -f $identity, $Trustee, $(if ($result.ResolvedUPN) { $result.ResolvedUPN } else { 'NULL' }))
        return $result
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

    if ($recipient) {
        # Prefer DistinguishedName (which Get-ADUser accepts); fall back to PrimarySmtpAddress
        # CRITICAL: Ensure DN is converted to string to avoid object-reference cache key issues
        $resolvedUpn = $recipient.DistinguishedName
        if ($resolvedUpn) {
            $resolvedUpn = $resolvedUpn.ToString().Trim()
        }
        if ([string]::IsNullOrEmpty($resolvedUpn) -and $recipient.PrimarySmtpAddress) {
            $resolvedUpn = $recipient.PrimarySmtpAddress.ToString()
        }
        if ($resolvedUpn) {
            # Store under both original and normalized keys so future lookups for the same user
            # (regardless of input format) reuse the exact same DN string
            $script:TrusteeCache[$Trustee] = $resolvedUpn
            if ($identity -ne $Trustee) {
                $script:TrusteeCache[$identity] = $resolvedUpn
            }
            $result.ResolvedUPN = $resolvedUpn
            Write-Verbose ("      [Resolve-Trustee] Resolved via Get-Recipient: {0}" -f $resolvedUpn)
            return $result
        }
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
        if ($identity -ne $Trustee) {
            $script:TrusteeCache[$identity] = $upn
        }
        $result.ResolvedUPN = $upn
        Write-Verbose ("      [Resolve-Trustee] Resolved via Get-ADUser: {0}" -f $upn)
        return $result
    }

    # Unresolved – mark as orphan if value looks like a SID
    Write-Verbose ("      [Resolve-Trustee] Failed to resolve '{0}' - caching SENTINEL" -f $Trustee)
    $script:TrusteeCache[$Trustee] = $script:SENTINEL
    if ($identity -ne $Trustee) {
        $script:TrusteeCache[$identity] = $script:SENTINEL
    }
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
        # Use the Alias (not SMTP address) for Get-MailboxFolderStatistics.
        # Passing an SMTP address can cause Exchange to misdirect the lookup to the
        # System Attendant object instead of the user mailbox on some configurations.
        $calFolder = Get-MailboxFolderStatistics -Identity $MailboxAlias -FolderScope Calendar -ErrorAction Stop |
        Where-Object { $_.FolderType -eq 'Calendar' -and -not $_.Movable } |
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
        Write-Warning ("Get-ADUser failed for '{0}': {1}" -f $SamAccountName, $_.Exception.Message)
        $script:ADUserCache[$SamAccountName] = $script:SENTINEL
        return $null
    }
}

#endregion

#region --- Trustee disabled check -----------------------------------------------

function Test-TrusteeIsDisabled {
    <#
    .SYNOPSIS
        Tests whether a trustee (by resolved UPN) has a disabled AD account.
        Only checks user accounts; group accounts are not considered.
    .PARAMETER ResolvedUPN
        The UPN of the trustee, typically from Resolve-Trustee output.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string]$ResolvedUPN
    )

    if (-not $ResolvedUPN) {
        Write-Verbose ("        [Test-TrusteeIsDisabled] ResolvedUPN is empty - returning False")
        return $false
    }

    # Check the dedicated trustee disabled cache first
    if ($script:TrusteeDisabledCache.ContainsKey($ResolvedUPN)) {
        $cached = $script:TrusteeDisabledCache[$ResolvedUPN]
        # IMPORTANT: Use type-check, not -eq, to distinguish bool values from the sentinel string.
        # PowerShell's -eq coerces types: ($true -eq '__NOT_FOUND__') evaluates $true because
        # [bool]'__NOT_FOUND__' = $true (non-empty string), causing disabled users to be
        # misidentified as SENTINEL and their permissions to be skipped.
        if ($cached -is [bool]) {
            Write-Verbose ("        [Test-TrusteeIsDisabled] Cache hit for '{0}': IsDisabled={1}" -f $ResolvedUPN, $cached)
            return $cached  # $true = disabled, $false = enabled
        }
        Write-Verbose ("        [Test-TrusteeIsDisabled] Cache hit for '{0}': SENTINEL (not a user)" -f $ResolvedUPN)
        return $false  # Sentinel string — not a user account
    }

    Write-Verbose ("        [Test-TrusteeIsDisabled] Cache miss - querying AD for: {0}" -f $ResolvedUPN)

    # Attempt to resolve the UPN to a user account (not groups)
    try {
        $adUser = Get-ADUser -Identity $ResolvedUPN -Properties Enabled -ErrorAction Stop

        # Cache the disabled state
        $isDisabled = -not $adUser.Enabled
        $script:TrusteeDisabledCache[$ResolvedUPN] = $isDisabled
        Write-Verbose ("        [Test-TrusteeIsDisabled] Found AD user '{0}' - Enabled: {1}, IsDisabled: {2} [Cached with key: {3}]" -f $adUser.SamAccountName, $adUser.Enabled, $isDisabled, $ResolvedUPN)
        return $isDisabled
    }
    catch {
        # Not a user (likely a group or doesn't exist as a user)
        # Cache sentinel so we don't retry the lookup
        $script:TrusteeDisabledCache[$ResolvedUPN] = $script:SENTINEL
        Write-Verbose ("        [Test-TrusteeIsDisabled] Failed to resolve '{0}' as user account (caching SENTINEL): {1}" -f $ResolvedUPN, $_.Exception.Message)
        return $false
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

    # Always process to check for disabled trustees, regardless of owner state or orphan mode
    # Resolve to plain strings to avoid deserialized-object identity errors in implicit remoting.
    # Get-MailboxPermission / Remove-MailboxPermission are more reliable with a Distinguished Name.
    $mailboxSmtp = $Mailbox.PrimarySmtpAddress.ToString()
    $mailboxDn = $Mailbox.DistinguishedName.ToString()

    Write-Verbose ("  Processing Full Access for: {0}" -f $mailboxSmtp)

    try {
        $permissions = Get-MailboxPermission -Identity $mailboxDn -ErrorAction Stop |
        Where-Object {
            $_.IsInherited -eq $false -and
            $_.Deny -eq $false -and
            $_.User -notmatch 'NT AUTHORITY\\SELF'
        }
    }
    catch {
        Write-Warning ("Get-MailboxPermission failed for '{0}': {1}" -f $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
        return
    }

    foreach ($perm in $permissions) {
        $trusteeRaw = $perm.User.ToString()
        $resolved = Resolve-Trustee -Trustee $trusteeRaw

        $trusteeIsDisabled = if ($resolved.ResolvedUPN) { Test-TrusteeIsDisabled -ResolvedUPN $resolved.ResolvedUPN } else { $false }

        $shouldRemove = $OwnerIsDisabled -or $trusteeIsDisabled -or ($IncludeOrphan -and $resolved.IsOrphanSid)
        if (-not $shouldRemove) { continue }

        $reason = if ($resolved.IsOrphanSid -and -not $OwnerIsDisabled -and -not $trusteeIsDisabled) {
            'Orphaned SID trustee - Full Access cleanup'
        }
        elseif ($trusteeIsDisabled) {
            'Disabled trustee - Full Access cleanup'
        }
        else {
            'Disabled mailbox owner account - Full Access cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal'] = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType'] = 'FullAccess'
        $entry['Reason'] = $reason

        $spDescription = "Remove Full Access for '{0}' on mailbox '{1}'" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress

        if ($PSCmdlet.ShouldProcess($spDescription, 'Remove-MailboxPermission')) {
            try {
                $removeMailboxPermissionParams = @{
                    Identity     = $mailboxDn
                    User         = $trusteeRaw
                    AccessRights = 'FullAccess'
                    Confirm      = $false
                    ErrorAction  = 'Stop'
                }
                Remove-MailboxPermission @removeMailboxPermissionParams
                $entry['RemovedAction'] = 'Removed'
                $entry['Success'] = $true
                $entry['ErrorMessage'] = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success'] = $false
                $entry['ErrorMessage'] = $_.Exception.Message
                Write-Warning ("Failed to remove Full Access for '{0}' on '{1}': {2}" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success'] = $true
            $entry['ErrorMessage'] = ''
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

    # Always process to check for disabled trustees, regardless of owner state or orphan mode
    # Resolve to plain strings to avoid deserialized-object identity errors in implicit remoting.
    # Get-ADPermission / Remove-ADPermission require a Distinguished Name; they do not resolve SMTP addresses.
    $mailboxSmtp = $Mailbox.PrimarySmtpAddress.ToString()
    $mailboxDn = $Mailbox.DistinguishedName.ToString()

    Write-Verbose ("  Processing Send As for: {0}" -f $mailboxSmtp)

    try {
        $adPerms = Get-ADPermission -Identity $mailboxDn -ErrorAction Stop |
        Where-Object {
            $_.ExtendedRights -match 'SendAs|Send-As' -and
            $_.IsInherited -eq $false -and
            $_.Deny -eq $false -and
            $_.User -notmatch 'NT AUTHORITY\\SELF'
        }
    }
    catch {
        Write-Warning ("Get-ADPermission failed for '{0}': {1}" -f $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
        return
    }

    if (@($adPerms).Count -eq 0) {
        Write-Verbose ("    No Send As permissions found to process.")
        return
    }

    Write-Verbose ("    Found {0} Send As permission(s) to evaluate." -f @($adPerms).Count)

    foreach ($perm in $adPerms) {
        $trusteeRaw = $perm.User.ToString()
        Write-Verbose ("    Processing Send As - User: {0}" -f $trusteeRaw)

        $resolved = Resolve-Trustee -Trustee $trusteeRaw
        Write-Verbose ("      Resolved UPN: {0}, IsOrphanSid: {1}" -f $(if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { 'UNRESOLVED' }), $resolved.IsOrphanSid)

        $trusteeIsDisabled = if ($resolved.ResolvedUPN) { Test-TrusteeIsDisabled -ResolvedUPN $resolved.ResolvedUPN } else { $false }
        Write-Verbose ("      TrusteeIsDisabled: {0}, OwnerIsDisabled: {1}, IncludeOrphan: {2}" -f $trusteeIsDisabled, $OwnerIsDisabled, $IncludeOrphan)

        $shouldRemove = $OwnerIsDisabled -or $trusteeIsDisabled -or ($IncludeOrphan -and $resolved.IsOrphanSid)
        if (-not $shouldRemove) { continue }

        $reason = if ($resolved.IsOrphanSid -and -not $OwnerIsDisabled -and -not $trusteeIsDisabled) {
            'Orphaned SID trustee - Send As cleanup'
        }
        elseif ($trusteeIsDisabled) {
            'Disabled trustee - Send As cleanup'
        }
        else {
            'Disabled mailbox owner account - Send As cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal'] = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType'] = 'SendAs'
        $entry['Reason'] = $reason

        $spDescription = "Remove Send As for '{0}' on mailbox '{1}'" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress

        if ($PSCmdlet.ShouldProcess($spDescription, 'Remove-ADPermission')) {
            try {
                $removeAdPermissionParams = @{
                    Identity       = $mailboxDn
                    User           = $trusteeRaw
                    ExtendedRights = 'Send-As'
                    Confirm        = $false
                    ErrorAction    = 'Stop'
                }
                Remove-ADPermission @removeAdPermissionParams
                $entry['RemovedAction'] = 'Removed'
                $entry['Success'] = $true
                $entry['ErrorMessage'] = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success'] = $false
                $entry['ErrorMessage'] = $_.Exception.Message
                Write-Warning ("Failed to remove Send As for '{0}' on '{1}': {2}" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success'] = $true
            $entry['ErrorMessage'] = ''
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
        is not applicable here; removes entries when mailbox owner or delegate is disabled.
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

    # Always process to check for disabled trustees, regardless of owner state
    # Resolve to a plain string to avoid deserialized-object identity errors in implicit remoting
    $mailboxSmtp = $Mailbox.PrimarySmtpAddress.ToString()

    Write-Verbose ("  Processing Send On Behalf for: {0}" -f $mailboxSmtp)

    $delegates = $Mailbox.GrantSendOnBehalfTo
    if (-not $delegates -or $delegates.Count -eq 0) {
        Write-Verbose ("    No Send On Behalf delegates found.")
        return
    }

    Write-Verbose ("    Found {0} Send On Behalf delegate(s)." -f $delegates.Count)

    foreach ($delegate in $delegates) {
        $trusteeRaw = $delegate.ToString()
        Write-Verbose ("    Processing delegate: {0}" -f $trusteeRaw)

        # Skip NT AUTHORITY\SELF (special permission for the object itself)
        if ($trusteeRaw -match 'NT AUTHORITY\\SELF') { continue }

        $resolved = Resolve-Trustee -Trustee $trusteeRaw
        Write-Verbose ("      Resolved UPN: {0}" -f $(if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { 'UNRESOLVED' }))

        $trusteeIsDisabled = if ($resolved.ResolvedUPN) { Test-TrusteeIsDisabled -ResolvedUPN $resolved.ResolvedUPN } else { $false }
        Write-Verbose ("      TrusteeIsDisabled: {0}, OwnerIsDisabled: {1}" -f $trusteeIsDisabled, $OwnerIsDisabled)

        $shouldRemove = $OwnerIsDisabled -or $trusteeIsDisabled
        Write-Verbose ("      ShouldRemove: {0}" -f $shouldRemove)
        if (-not $shouldRemove) { continue }

        $reason = if ($trusteeIsDisabled) {
            'Disabled trustee - Send On Behalf cleanup'
        }
        else {
            'Disabled mailbox owner account - Send On Behalf cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal'] = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType'] = 'SendOnBehalf'
        $entry['Reason'] = $reason

        $spDescription = "Remove Send On Behalf delegate '{0}' from mailbox '{1}'" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress

        if ($PSCmdlet.ShouldProcess($spDescription, 'Set-Mailbox')) {
            try {
                $setMailboxParams = @{
                    Identity            = $mailboxSmtp
                    GrantSendOnBehalfTo = @{ Remove = $trusteeRaw }
                    Confirm             = $false
                    ErrorAction         = 'Stop'
                }
                Set-Mailbox @setMailboxParams
                $entry['RemovedAction'] = 'Removed'
                $entry['Success'] = $true
                $entry['ErrorMessage'] = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success'] = $false
                $entry['ErrorMessage'] = $_.Exception.Message
                Write-Warning ("Failed to remove Send On Behalf for '{0}' on '{1}': {2}" -f $trusteeRaw, $Mailbox.PrimarySmtpAddress, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success'] = $true
            $entry['ErrorMessage'] = ''
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

    # Always process to check for disabled trustees, regardless of owner state or orphan mode
    # Resolve to a plain string to avoid deserialized-object identity errors in implicit remoting
    $mailboxSmtp = $Mailbox.PrimarySmtpAddress.ToString()

    Write-Verbose ("  Processing Calendar permissions for: {0}" -f $mailboxSmtp)

    $calPath = Get-CalendarFolderPath -MailboxIdentity $mailboxSmtp -MailboxAlias $Mailbox.Alias

    if (-not $calPath) {
        Write-Warning ("Could not determine calendar folder path for '{0}'. Skipping." -f $Mailbox.PrimarySmtpAddress)
        return
    }

    Write-Verbose ("    Calendar folder path: {0}" -f $calPath)

    try {
        $calPerms = Get-MailboxFolderPermission -Identity $calPath -ErrorAction Stop |
        Where-Object {
            $_.User.DisplayName -ne 'Default' -and
            $_.User.DisplayName -ne 'Anonymous' -and
            $_.User.DisplayName -ne 'SELF'
        }
    }
    catch {
        Write-Warning ("Get-MailboxFolderPermission failed for '{0}': {1}" -f $calPath, $_.Exception.Message)
        return
    }

    if (@($calPerms).Count -eq 0) {
        Write-Verbose ("    No calendar permissions found to process.")
        return
    }

    Write-Verbose ("    Found {0} calendar permission(s) to evaluate." -f @($calPerms).Count)

    foreach ($perm in $calPerms) {
        # For calendar permissions, use ToString() to get the user identity
        $trusteeRaw = $perm.User.ToString()

        Write-Verbose ("    Processing calendar permission - TrusteeRaw: {0}, DisplayName: {1}" -f $trusteeRaw, $perm.User.DisplayName)

        $resolved = Resolve-Trustee -Trustee $trusteeRaw
        Write-Verbose ("      Resolved UPN: {0}, IsOrphanSid: {1}" -f $(if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { 'UNRESOLVED' }), $resolved.IsOrphanSid)

        $trusteeIsDisabled = if ($resolved.ResolvedUPN) { Test-TrusteeIsDisabled -ResolvedUPN $resolved.ResolvedUPN } else { $false }
        Write-Verbose ("      TrusteeIsDisabled: {0}, OwnerIsDisabled: {1}, IncludeOrphan: {2}" -f $trusteeIsDisabled, $OwnerIsDisabled, $IncludeOrphan)

        $shouldRemove = $OwnerIsDisabled -or $trusteeIsDisabled -or ($IncludeOrphan -and $resolved.IsOrphanSid)
        if (-not $shouldRemove) { continue }

        $reason = if ($resolved.IsOrphanSid -and -not $OwnerIsDisabled -and -not $trusteeIsDisabled) {
            'Orphaned SID trustee - Calendar permission cleanup'
        }
        elseif ($trusteeIsDisabled) {
            'Disabled trustee - Calendar permission cleanup'
        }
        else {
            'Disabled mailbox owner account - Calendar permission cleanup'
        }

        $entry = $BaseEntry.Clone()
        $entry['TrusteeOriginal'] = $trusteeRaw
        $entry['TrusteeResolvedUPN'] = if ($resolved.ResolvedUPN) { $resolved.ResolvedUPN } else { '' }
        $entry['PermissionType'] = 'CalendarPermission'
        $entry['Reason'] = $reason

        $spDescription = "Remove Calendar permission for '{0}' on '{1}'" -f $trusteeRaw, $calPath

        if ($PSCmdlet.ShouldProcess($spDescription, 'Remove-MailboxFolderPermission')) {
            try {
                $removeCalendarPermissionParams = @{
                    Identity    = $calPath
                    User        = $trusteeRaw
                    Confirm     = $false
                    ErrorAction = 'Stop'
                }
                Remove-MailboxFolderPermission @removeCalendarPermissionParams
                $entry['RemovedAction'] = 'Removed'
                $entry['Success'] = $true
                $entry['ErrorMessage'] = ''
            }
            catch {
                $entry['RemovedAction'] = 'Failed'
                $entry['Success'] = $false
                $entry['ErrorMessage'] = $_.Exception.Message
                Write-Warning ("Failed to remove Calendar permission for '{0}' on '{1}': {2}" -f $trusteeRaw, $calPath, $_.Exception.Message)
            }
        }
        else {
            $entry['RemovedAction'] = 'WhatIf'
            $entry['Success'] = $true
            $entry['ErrorMessage'] = ''
        }

        Write-LogEntry -Entry $entry
    }
}

#endregion

#region --- Main script body -----------------------------------------------------

if ($WhatIfPreference) {
    Write-Host "Running in WhatIf mode - no changes will be made. Findings will be written to the pipeline."
}
else {
    Write-Host ("Log file: {0}" -f $LogPath)
}

# Auto-detect multi-domain forest and enable ViewEntireForest if needed
Write-Verbose "Checking Active Directory forest topology..."
try {
    $adForest = Get-ADForest -ErrorAction Stop
    if ($adForest.Domains.Count -gt 1) {
        Write-Verbose ("Forest '{0}' contains {1} domains - enabling ViewEntireForest." -f $adForest.Name, $adForest.Domains.Count)
        try {
            Set-ADServerSettings -ViewEntireForest $true -ErrorAction Stop
            Write-Verbose "ViewEntireForest is now enabled."
        }
        catch {
            Write-Warning ("Failed to set ViewEntireForest: {0}" -f $_.Exception.Message)
        }
    }
    else {
        Write-Verbose ("Single-domain forest '{0}' - ViewEntireForest not required." -f $adForest.Name)
    }
}
catch {
    Write-Warning ("Could not determine forest topology: {0}" -f $_.Exception.Message)
}

Write-Verbose "Retrieving mailboxes..."

try {
    $getMailboxParams = @{
        ResultSize           = $ResultSize
        RecipientTypeDetails = 'UserMailbox'
        ErrorAction          = 'Stop'
    }
    $allMailboxes = @(Get-Mailbox @getMailboxParams)
}
catch {
    throw ("Failed to retrieve mailboxes: {0}" -f $_.Exception.Message)
}

$total = $allMailboxes.Count
$current = 0

Write-Host ("Found {0} UserMailbox recipients." -f $total)

foreach ($mbx in $allMailboxes) {
    $current++
    $progressParams = @{
        Activity        = 'Invoke-MailboxPermissionCleaner'
        Status          = ("Processing {0} of {1}: {2}" -f $current, $total, $mbx.PrimarySmtpAddress)
        PercentComplete = ($current / $total) * 100
    }
    Write-Progress @progressParams

    Write-Verbose ("[{0}/{1}] Checking: {2}" -f $current, $total, $mbx.PrimarySmtpAddress)

    # --- Determine if the mailbox owner AD account is disabled ---
    $ownerSam = $mbx.SamAccountName
    $ownerDisabled = $false
    $adUser = $null

    if ([string]::IsNullOrWhiteSpace($ownerSam)) {
        Write-Verbose ("  No SamAccountName found.")
    }
    else {
        $adUser = Get-MailboxOwnerADUser -SamAccountName $ownerSam
        if (-not $adUser) {
            Write-Warning ("Could not retrieve AD account for '{0}' - mailbox will be skipped." -f $ownerSam)
        }
        elseif ($adUser.Enabled -eq $false) {
            $ownerDisabled = $true
            Write-Verbose ("  Account '{0}' is DISABLED." -f $ownerSam)
        }
        else {
            Write-Verbose ("  Account '{0}' is enabled." -f $ownerSam)
        }
    }

    # Process all mailboxes to check for disabled trustees and orphaned permissions
    # Do NOT skip enabled-owner mailboxes – disabled trustees should be detected regardless

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

    $permissionParams = @{
        Mailbox         = $mbx
        BaseEntry       = $baseEntry
        OwnerIsDisabled = $ownerDisabled
        Verbose         = ($VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue)
    }

    if ($FullAccess) {
        try {
            Remove-FullAccessPermissions @permissionParams -IncludeOrphan ([bool]$Orphan)
        }
        catch {
            Write-Warning ("Unexpected error in Remove-FullAccessPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }

    if ($SendAs) {
        try {
            Remove-SendAsPermissions @permissionParams -IncludeOrphan ([bool]$Orphan)
        }
        catch {
            Write-Warning ("Unexpected error in Remove-SendAsPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }

    if ($SendOnBehalfOf) {
        try {
            Remove-SendOnBehalfPermissions @permissionParams
        }
        catch {
            Write-Warning ("Unexpected error in Remove-SendOnBehalfPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }

    if ($Calendar) {
        try {
            Remove-CalendarPermissions @permissionParams -IncludeOrphan ([bool]$Orphan)
        }
        catch {
            Write-Warning ("Unexpected error in Remove-CalendarPermissions for '{0}': {1}" -f $mbx.PrimarySmtpAddress, $_.Exception.Message)
        }
    }
}

Write-Progress -Activity 'Invoke-MailboxPermissionCleaner' -Completed
if ($WhatIfPreference) {
    Write-Host ("Processing complete. {0} finding(s) reported (WhatIf - no changes made)." -f $script:LogEntryCount)
}
elseif ($script:LogEntryCount -gt 0) {
    Write-Host ("Processing complete. {0} entr{1} written to: {2}" -f $script:LogEntryCount, $(if ($script:LogEntryCount -eq 1) { 'y' } else { 'ies' }), $LogPath)
}
else {
    Write-Host "Processing complete. No qualifying permissions were found; no log file was created."
}

#endregion
