#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$OutDir = "C:\Temp\EntraUsersReport"
$ReportPath = Join-Path $OutDir "EntraUsers_Duplicates_Report.xlsx"

$RequiredModules = @('Microsoft.Graph','ImportExcel')
$GraphScopes = @('User.Read.All','Directory.Read.All','AuditLog.Read.All')

$UserProperties = @(
    'Id',
    'DisplayName',
    'UserPrincipalName',
    'Mail',
    'UserType',
    'AccountEnabled',
    'CreatedDateTime',
    'OnPremisesSyncEnabled',
    'OnPremisesImmutableId',
    'OnPremisesDomainName',
    'OnPremisesSamAccountName',
    'ProxyAddresses',
    'Department',
    'JobTitle',
    'EmployeeId'
)

$ReportColumns = @(
    'DisplayName',
    'UserPrincipalName',
    'UPNPrefix',
    'Mail',
    'UserType',
    'AccountEnabled',
    'CreatedDateTime',
    'OnPremisesSyncEnabled',
    'Source',
    'OnPremisesDomainName',
    'OnPremisesSamAccountName',
    'OnPremisesImmutableId',
    'Department',
    'JobTitle',
    'EmployeeId',
    'ProxyAddresses',
    'DuplicateType',
    'DuplicateValue',
    'DuplicateCount'
)

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Ensure-Module {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Info "Module '$Name' not found. Installing in CurrentUser scope..."
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        catch {
            throw "Failed to install module '$Name'. Error: $($_.Exception.Message)"
        }
    }

    try {
        Import-Module -Name $Name -ErrorAction Stop
    }
    catch {
        throw "Failed to import module '$Name'. Error: $($_.Exception.Message)"
    }
}

function Get-UPNPrefix {
    param([string]$UserPrincipalName)

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        return $null
    }

    $parts = $UserPrincipalName.Split('@',2)
    if ($parts.Count -gt 0) { return $parts[0].ToLowerInvariant() }
    return $null
}

function Convert-ToReportUser {
    param(
        [Parameter(Mandatory)]$User,
        [string]$DuplicateType = $null,
        [string]$DuplicateValue = $null,
        [int]$DuplicateCount = 0
    )

    $proxyString = if ($User.ProxyAddresses) { ($User.ProxyAddresses -join '; ') } else { $null }
    $source = if ($User.OnPremisesSyncEnabled -eq $true) { 'Synced from on-prem AD' } else { 'Cloud-only / Manual or cloud-created' }

    [pscustomobject]@{
        DisplayName                = $User.DisplayName
        UserPrincipalName          = $User.UserPrincipalName
        UPNPrefix                  = Get-UPNPrefix -UserPrincipalName $User.UserPrincipalName
        Mail                       = $User.Mail
        UserType                   = $User.UserType
        AccountEnabled             = $User.AccountEnabled
        CreatedDateTime            = $User.CreatedDateTime
        OnPremisesSyncEnabled      = $User.OnPremisesSyncEnabled
        Source                     = $source
        OnPremisesDomainName       = $User.OnPremisesDomainName
        OnPremisesSamAccountName   = $User.OnPremisesSamAccountName
        OnPremisesImmutableId      = $User.OnPremisesImmutableId
        Department                 = $User.Department
        JobTitle                   = $User.JobTitle
        EmployeeId                 = $User.EmployeeId
        ProxyAddresses             = $proxyString
        DuplicateType              = $DuplicateType
        DuplicateValue             = $DuplicateValue
        DuplicateCount             = $DuplicateCount
    }
}

function Get-DuplicatesByProperty {
    param(
        [Parameter(Mandatory)]$Users,
        [Parameter(Mandatory)][string]$PropertyName,
        [Parameter(Mandatory)][string]$DuplicateType
    )

    $groups = $Users |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.$PropertyName) } |
        Group-Object -Property $PropertyName |
        Where-Object { $_.Count -gt 1 }

    $result = foreach ($g in $groups) {
        foreach ($u in $g.Group) {
            Convert-ToReportUser -User $u -DuplicateType $DuplicateType -DuplicateValue ([string]$g.Name) -DuplicateCount $g.Count
        }
    }

    $result | Sort-Object DuplicateValue, UserPrincipalName
}

function Get-DuplicatesByProxyAddress {
    param([Parameter(Mandatory)]$Users)

    $expanded = foreach ($u in $Users) {
        if (-not $u.ProxyAddresses) { continue }

        foreach ($addr in $u.ProxyAddresses) {
            if ([string]::IsNullOrWhiteSpace($addr)) { continue }
            if ($addr -notmatch '(?i)^smtp:') { continue }

            $normalized = ($addr -replace '(?i)^smtp:', '').Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($normalized)) { continue }

            [pscustomobject]@{
                Address = $normalized
                User    = $u
            }
        }
    }

    $dupeGroups = $expanded |
        Group-Object -Property Address |
        Where-Object { $_.Count -gt 1 }

    $result = foreach ($g in $dupeGroups) {
        foreach ($item in $g.Group) {
            Convert-ToReportUser -User $item.User -DuplicateType 'ProxyAddress' -DuplicateValue $g.Name -DuplicateCount $g.Count
        }
    }

    $result | Sort-Object DuplicateValue, UserPrincipalName
}

function Get-SuspiciousUsers {
    param([Parameter(Mandatory)]$Users)

    $index = @{}

    $displayGroups = $Users |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.DisplayName) } |
        Group-Object -Property DisplayName |
        Where-Object { $_.Count -gt 1 }

    foreach ($g in $displayGroups) {
        $hasSynced = ($g.Group | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count -gt 0
        $hasCloud  = ($g.Group | Where-Object { $_.OnPremisesSyncEnabled -ne $true }).Count -gt 0

        if ($hasSynced -and $hasCloud) {
            foreach ($u in $g.Group) {
                $key = "$($u.Id)|DisplayName|$($g.Name)"
                if (-not $index.ContainsKey($key)) {
                    $index[$key] = Convert-ToReportUser -User $u -DuplicateType 'DisplayName' -DuplicateValue ([string]$g.Name) -DuplicateCount $g.Count
                }
            }
        }
    }

    $upnPrepared = $Users | ForEach-Object {
        [pscustomobject]@{
            User      = $_
            UPNPrefix = Get-UPNPrefix -UserPrincipalName $_.UserPrincipalName
        }
    }

    $upnGroups = $upnPrepared |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.UPNPrefix) } |
        Group-Object -Property UPNPrefix |
        Where-Object { $_.Count -gt 1 }

    foreach ($g in $upnGroups) {
        $groupUsers = $g.Group.User
        $hasSynced = ($groupUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count -gt 0
        $hasCloud  = ($groupUsers | Where-Object { $_.OnPremisesSyncEnabled -ne $true }).Count -gt 0

        if ($hasSynced -and $hasCloud) {
            foreach ($u in $groupUsers) {
                $key = "$($u.Id)|UPNPrefix|$($g.Name)"
                if (-not $index.ContainsKey($key)) {
                    $index[$key] = Convert-ToReportUser -User $u -DuplicateType 'UPNPrefix' -DuplicateValue ([string]$g.Name) -DuplicateCount $g.Count
                }
            }
        }
    }

    $index.Values | Sort-Object DuplicateType, DuplicateValue, UserPrincipalName
}

function Select-ReportColumns {
    param($Data)
    $Data | Select-Object -Property $ReportColumns
}

function Get-ExcelColumnLetter {
    param([Parameter(Mandatory)][int]$ColumnNumber)

    $dividend = $ColumnNumber
    $columnName = ''
    while ($dividend -gt 0) {
        $modulo = ($dividend - 1) % 26
        $columnName = [char](65 + $modulo) + $columnName
        $dividend = [math]::Floor(($dividend - $modulo) / 26)
    }

    return $columnName
}

function Export-ReportSheet {
    param(
        [Parameter(Mandatory)][string]$WorksheetName,
        $Data,
        [Parameter(Mandatory)][string]$Path,
        [switch]$Clear
    )

    $tableName = ('T_' + ($WorksheetName -replace '[^A-Za-z0-9]','_'))
    if ($tableName.Length -gt 30) {
        $tableName = $tableName.Substring(0,30)
    }

    if ($null -eq $Data -or @($Data).Count -eq 0) {
        $Data = @([pscustomobject]@{ Message = 'No records found' })
    }

    $params = @{
        Path          = $Path
        WorksheetName = $WorksheetName
        TableName     = $tableName
        AutoSize      = $true
        AutoFilter    = $true
        FreezeTopRow  = $true
        BoldTopRow    = $true
        ErrorAction   = 'Stop'
    }

    if ($Clear) {
        $params.ClearSheet = $true
    }
    else {
        $params.Append = $true
    }

    $Data | Export-Excel @params
}

try {
    Write-Info 'Checking required modules...'
    foreach ($m in $RequiredModules) {
        Ensure-Module -Name $m
    }

    if (-not (Test-Path -Path $OutDir)) {
        Write-Info "Creating output folder: $OutDir"
        New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    }

    if (Test-Path -Path $ReportPath) {
        Remove-Item -Path $ReportPath -Force
    }

    Write-Info 'Connecting to Microsoft Graph...'
    try {
        Connect-MgGraph -Scopes $GraphScopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    catch {
        throw "Failed to connect to Microsoft Graph or insufficient permissions. Error: $($_.Exception.Message)"
    }

    Write-Info 'Retrieving users from Microsoft Graph...'
    $allUsers = @()
    try {
        $allUsers = Get-MgUser -All -Property $UserProperties -ErrorAction Stop
    }
    catch {
        throw "Get-MgUser failed. Verify Graph permissions and tenant access. Error: $($_.Exception.Message)"
    }

    Write-Info "Total users retrieved: $($allUsers.Count)"

    Write-Info 'Preparing datasets...'
    $allReport = @($allUsers | ForEach-Object { Convert-ToReportUser -User $_ } | Select-ReportColumns)
    $cloudOnly = @($allUsers |
        Where-Object { $_.OnPremisesSyncEnabled -ne $true } |
        ForEach-Object { Convert-ToReportUser -User $_ } |
        Select-ReportColumns)

    $dupDisplay = @(Get-DuplicatesByProperty -Users $allUsers -PropertyName 'DisplayName' -DuplicateType 'DisplayName' | Select-ReportColumns)
    $dupMail    = @(Get-DuplicatesByProperty -Users $allUsers -PropertyName 'Mail' -DuplicateType 'Mail' | Select-ReportColumns)

    $usersWithUpnPrefix = $allUsers | ForEach-Object {
        [pscustomobject]@{
            User      = $_
            UPNPrefix = Get-UPNPrefix -UserPrincipalName $_.UserPrincipalName
        }
    }
    $upnGroups = $usersWithUpnPrefix |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.UPNPrefix) } |
        Group-Object -Property UPNPrefix |
        Where-Object { $_.Count -gt 1 }
    $dupUpnPrefix = @(foreach ($g in $upnGroups) {
        foreach ($item in $g.Group) {
            Convert-ToReportUser -User $item.User -DuplicateType 'UPNPrefix' -DuplicateValue $g.Name -DuplicateCount $g.Count
        }
    })
    $dupUpnPrefix = @($dupUpnPrefix | Sort-Object DuplicateValue, UserPrincipalName | Select-ReportColumns)

    $dupProxy = @(Get-DuplicatesByProxyAddress -Users $allUsers | Select-ReportColumns)
    $suspicious = @(Get-SuspiciousUsers -Users $allUsers | Select-ReportColumns)

    $syncedCount = ($allUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true }).Count
    $cloudCount  = ($allUsers | Where-Object { $_.OnPremisesSyncEnabled -ne $true }).Count

    $summary = @(
        [pscustomobject]@{ Metric = 'RunDateUtc'; Value = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC') },
        [pscustomobject]@{ Metric = 'TotalUsers'; Value = $allUsers.Count },
        [pscustomobject]@{ Metric = 'SyncedFromAD'; Value = $syncedCount },
        [pscustomobject]@{ Metric = 'CloudOnly'; Value = $cloudCount },
        [pscustomobject]@{ Metric = 'DuplicateDisplayNameRows'; Value = $dupDisplay.Count },
        [pscustomobject]@{ Metric = 'DuplicateMailRows'; Value = $dupMail.Count },
        [pscustomobject]@{ Metric = 'DuplicateUPNPrefixRows'; Value = $dupUpnPrefix.Count },
        [pscustomobject]@{ Metric = 'DuplicateProxyAddressRows'; Value = $dupProxy.Count },
        [pscustomobject]@{ Metric = 'SuspiciousRowsSyncedPlusCloud'; Value = $suspicious.Count },
        [pscustomobject]@{ Metric = 'ReportPath'; Value = $ReportPath }
    )

    Write-Info 'Exporting Excel report...'

    Export-ReportSheet -WorksheetName '00_Summary' -Data $summary -Path $ReportPath -Clear
    Export-ReportSheet -WorksheetName '07_Suspicious' -Data $suspicious -Path $ReportPath
    Export-ReportSheet -WorksheetName '01_All_Users' -Data $allReport -Path $ReportPath
    Export-ReportSheet -WorksheetName '02_CloudOnly_Manual' -Data $cloudOnly -Path $ReportPath
    Export-ReportSheet -WorksheetName '03_Dup_DisplayName' -Data $dupDisplay -Path $ReportPath
    Export-ReportSheet -WorksheetName '04_Dup_Mail' -Data $dupMail -Path $ReportPath
    Export-ReportSheet -WorksheetName '05_Dup_UPNPrefix' -Data $dupUpnPrefix -Path $ReportPath
    Export-ReportSheet -WorksheetName '06_Dup_ProxyAddresses' -Data $dupProxy -Path $ReportPath

    try {
        $excel = Open-ExcelPackage -Path $ReportPath -ErrorAction Stop

        $wsSuspicious = $excel.Workbook.Worksheets['07_Suspicious']
        if ($wsSuspicious -and $wsSuspicious.Dimension) {
            $endRow = $wsSuspicious.Dimension.End.Row
            $endCol = $wsSuspicious.Dimension.End.Column
            if ($endRow -ge 2 -and $endCol -ge 1) {
                $endColLetter = Get-ExcelColumnLetter -ColumnNumber $endCol
                $sheetRange = "A2:{0}{1}" -f $endColLetter, $endRow

                $headerMap = @{}
                for ($c = 1; $c -le $endCol; $c++) {
                    $headerMap[$wsSuspicious.Cells[1,$c].Text] = $c
                }

                if ($headerMap.ContainsKey('Source')) {
                    $srcCol = $headerMap['Source']
                    $srcColLetter = Get-ExcelColumnLetter -ColumnNumber $srcCol
                    Add-ConditionalFormatting -Worksheet $wsSuspicious -Address $sheetRange -RuleType Expression -ConditionValue "=\$$srcColLetter`2=""Cloud-only / Manual or cloud-created""" -ForegroundColor Black -BackgroundColor '#FFF2CC' -StopIfTrue:$false -ErrorAction Stop -PassThru | Out-Null
                    Add-ConditionalFormatting -Worksheet $wsSuspicious -Address $sheetRange -RuleType Expression -ConditionValue "=\$$srcColLetter`2=""Synced from on-prem AD""" -ForegroundColor Black -BackgroundColor '#E2F0D9' -StopIfTrue:$false -ErrorAction Stop -PassThru | Out-Null
                }

                if ($headerMap.ContainsKey('AccountEnabled')) {
                    $enabledCol = $headerMap['AccountEnabled']
                    $enabledColLetter = Get-ExcelColumnLetter -ColumnNumber $enabledCol
                    Add-ConditionalFormatting -Worksheet $wsSuspicious -Address $sheetRange -RuleType Expression -ConditionValue "=\$$enabledColLetter`2=FALSE" -ForegroundColor Black -BackgroundColor '#F8CBAD' -StopIfTrue:$false -ErrorAction Stop -PassThru | Out-Null
                }
            }
        }

        Close-ExcelPackage -ExcelPackage $excel -ErrorAction Stop
    }
    catch {
        throw "Failed to format/save Excel workbook. Error: $($_.Exception.Message)"
    }

    Write-Host "`nReport created successfully: $ReportPath" -ForegroundColor Green
    Write-Host "Done. Output Excel file: $ReportPath" -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    try { Disconnect-MgGraph | Out-Null } catch { }
}
