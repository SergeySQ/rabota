[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1,365)]
    [int]$DaysBack = 30,

    [Parameter(Mandatory = $false)]
    [string]$OutDir = 'C:\Temp\SMTP-Audit'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Stage {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Join-ExchangeArray {
    param($Value)

    if ($null -eq $Value) { return '' }

    if ($Value -is [string]) { return $Value }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -ne $item) {
                $items += [string]$item
            }
        }
        return ($items -join ';')
    }

    return [string]$Value
}

function Normalize-SmtpEndpoint {
    param([string]$RawValue)

    if ([string]::IsNullOrWhiteSpace($RawValue)) { return $null }

    $value = $RawValue.Trim()

    if ($value -match '^(?i)smtp:') {
        $value = $value -replace '^(?i)smtp:', ''
    }

    if ($value -match ';') {
        $value = $value.Split(';')[0].Trim()
    }

    if ($value -match '^\[(.+)\]$') {
        $value = $matches[1]
    }

    $value = $value.Trim()

    if ([string]::IsNullOrWhiteSpace($value)) { return $null }
    if ($value -eq '*') { return $null }
    if ($value -eq 'SMTP:*') { return $null }

    return $value
}

function Test-IpRangeIsWideOpen {
    param($Ranges)

    if ($null -eq $Ranges) { return $false }

    foreach ($range in $Ranges) {
        $s = [string]$range
        if ($s -match '0\.0\.0\.0-255\.255\.255\.255' -or $s -match '^0\.0\.0\.0$') {
            return $true
        }
        if ($s -match '::/0' -or $s -match '0:0:0:0:0:0:0:0-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') {
            return $true
        }
    }

    return $false
}

function Invoke-DnsTcpAudit {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Endpoints
    )

    $results = @()

    foreach ($endpoint in $Endpoints) {
        $normalized = Normalize-SmtpEndpoint -RawValue $endpoint.Endpoint
        if ([string]::IsNullOrWhiteSpace($normalized)) { continue }

        $isIp = [System.Net.IPAddress]::TryParse($normalized, [ref]([System.Net.IPAddress]::Any))
        $aRecords = @()
        $mxRecords = @()
        $tcp25 = $false
        $mxTcpResults = @()
        $errors = @()

        if (-not $isIp) {
            try {
                $aLookup = Resolve-DnsName -Name $normalized -Type A -ErrorAction Stop
                $aRecords = @($aLookup | ForEach-Object { $_.IPAddress } | Where-Object { $_ })
            } catch {
                $errors += "A lookup failed: $($_.Exception.Message)"
            }

            try {
                $mxLookup = Resolve-DnsName -Name $normalized -Type MX -ErrorAction Stop
                $mxRecords = @($mxLookup | Sort-Object Preference | ForEach-Object { $_.NameExchange.TrimEnd('.') } | Where-Object { $_ })
            } catch {
                $errors += "MX lookup failed: $($_.Exception.Message)"
            }
        }

        try {
            $tcp = Test-NetConnection -ComputerName $normalized -Port 25 -WarningAction SilentlyContinue
            $tcp25 = [bool]$tcp.TcpTestSucceeded
        } catch {
            $errors += "TCP25 failed: $($_.Exception.Message)"
        }

        foreach ($mx in $mxRecords) {
            $mxTcp = $false
            try {
                $mxTcpResult = Test-NetConnection -ComputerName $mx -Port 25 -WarningAction SilentlyContinue
                $mxTcp = [bool]$mxTcpResult.TcpTestSucceeded
            } catch {
                $errors += "MX TCP25 failed ($mx): $($_.Exception.Message)"
            }

            $mxTcpResults += [PSCustomObject]@{
                MXHost = $mx
                Tcp25  = $mxTcp
            }
        }

        $dnsOk = $false
        if ($isIp) {
            $dnsOk = $true
        } elseif ($aRecords.Count -gt 0 -or $mxRecords.Count -gt 0) {
            $dnsOk = $true
        }

        $mxFailed = ($mxTcpResults | Where-Object { -not $_.Tcp25 }).Count -gt 0
        $status = if (-not $dnsOk -or -not $tcp25 -or $mxFailed) { 'IssueDetected' } else { 'OK' }

        $results += [PSCustomObject]@{
            SourceType      = $endpoint.SourceType
            SourceObject    = $endpoint.SourceObject
            RawValue        = $endpoint.Endpoint
            NormalizedValue = $normalized
            IsIpAddress     = $isIp
            ARecords        = ($aRecords -join ';')
            MXRecords       = ($mxRecords -join ';')
            Tcp25ToEndpoint = $tcp25
            MxTcp25Summary  = (($mxTcpResults | ForEach-Object { "$($_.MXHost)=$($_.Tcp25)" }) -join ';')
            DnsResolved     = $dnsOk
            Status          = $status
            Errors          = ($errors -join ' | ')
        }
    }

    return $results
}

$reportFiles = @()
$reviewCandidates = @()

try {
    Write-Stage "Подготовка каталога отчета: $OutDir"
    if (-not (Test-Path -Path $OutDir)) {
        New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    }

    $startDate = (Get-Date).AddDays(-$DaysBack)
    $endDate = Get-Date
    $eventsOfInterest = @('SEND','RECEIVE','FAIL','DELIVER','HAREDIRECT','HADISCARD')

    Write-Stage "Получение списка серверов Exchange Transport"
    $transportServers = @(Get-TransportService | Select-Object -ExpandProperty Name)
    if ($transportServers.Count -eq 0) {
        throw 'Не найдено серверов TransportService (Get-TransportService вернул пусто).'
    }

    Write-Stage "Сбор Message Tracking логов за период $DaysBack дней (с $startDate по $endDate)"
    $rawTracking = @()
    foreach ($srv in $transportServers) {
        Write-Host "  -> Сервер: $srv" -ForegroundColor DarkCyan
        try {
            $chunk = Get-MessageTrackingLog -Server $srv -Start $startDate -End $endDate -EventId $eventsOfInterest -ResultSize Unlimited
            foreach ($row in $chunk) {
                $rawTracking += [PSCustomObject]@{
                    Timestamp       = $row.Timestamp
                    ServerHostname  = $row.ServerHostname
                    EventId         = $row.EventId
                    Source          = $row.Source
                    Sender          = $row.Sender
                    Recipients      = (Join-ExchangeArray -Value $row.Recipients)
                    MessageSubject  = $row.MessageSubject
                    ClientIp        = $row.ClientIp
                    ClientHostname  = $row.ClientHostname
                    ConnectorId     = $row.ConnectorId
                    RecipientStatus = (Join-ExchangeArray -Value $row.RecipientStatus)
                }
            }
        } catch {
            Write-Host "  ! Ошибка на $srv: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    $rawTrackingFile = Join-Path $OutDir 'MessageTracking-Raw.csv'
    $rawTracking | Sort-Object Timestamp | Export-Csv -Path $rawTrackingFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $rawTrackingFile

    Write-Stage "Сбор Send Connectors"
    $sendConnectors = @(Get-SendConnector)

    $sendAudit = @()
    foreach ($sc in $sendConnectors) {
        try {
            $scName = [string]$sc.Name
            $scTracking = @($rawTracking | Where-Object {
                $_.ConnectorId -and (
                    $_.ConnectorId -like "*$scName*" -or
                    $_.ConnectorId -like "*$($sc.Identity)*"
                )
            })
            $sendCount = @($scTracking | Where-Object { $_.EventId -eq 'SEND' }).Count
            $failCount = @($scTracking | Where-Object { $_.EventId -eq 'FAIL' }).Count
            $lastUsed = ($scTracking | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp

            $addressSpacesString = Join-ExchangeArray -Value $sc.AddressSpaces
            $auditStatus = 'Used'
            $recommendedAction = 'Keep in production; monitor periodically.'

            if (-not $sc.Enabled) {
                $auditStatus = 'Disabled'
                $recommendedAction = 'Disabled connector; validate ownership before removal.'
            } elseif ($addressSpacesString -match '(?i)kgmukz\.mail\.onmicrosoft\.com') {
                $auditStatus = 'HybridConnector_CheckCarefully'
                $recommendedAction = 'Hybrid route; do NOT remove automatically. Validate with M365 mail flow owner.'
            } elseif ($addressSpacesString -match '(?i)^smtp:\*;?\d*$' -or $addressSpacesString -match '(?i)SMTP:\*') {
                $auditStatus = 'DefaultExternalRoute_CheckCarefully'
                $recommendedAction = 'Default external route; do NOT remove automatically. Validate relay dependency (FortiMail/main egress).'
            } elseif ($sendCount -eq 0) {
                $auditStatus = 'NoUsageFound_CandidateForReview'
                $recommendedAction = 'No SEND usage found in period; verify business owner before decommission.'
            }

            if ($failCount -gt 0) {
                $reviewCandidates += [PSCustomObject]@{
                    ObjectType        = 'SendConnector'
                    Name              = $scName
                    Status            = 'FailEventsDetected'
                    Risk              = 'Medium'
                    Details           = "FAIL events: $failCount in last $DaysBack days"
                    RecommendedAction = 'Review queue/reachability and connector settings.'
                }
            }

            if ($auditStatus -eq 'NoUsageFound_CandidateForReview') {
                $reviewCandidates += [PSCustomObject]@{
                    ObjectType        = 'SendConnector'
                    Name              = $scName
                    Status            = $auditStatus
                    Risk              = 'Low'
                    Details           = "No SEND events in last $DaysBack days"
                    RecommendedAction = $recommendedAction
                }
            }

            $sendAudit += [PSCustomObject]@{
                Name                   = $scName
                Enabled                = $sc.Enabled
                AddressSpaces          = $addressSpacesString
                SmartHosts             = (Join-ExchangeArray -Value $sc.SmartHosts)
                DNSRoutingEnabled      = $sc.DNSRoutingEnabled
                SourceTransportServers = (Join-ExchangeArray -Value $sc.SourceTransportServers)
                MaxMessageSize         = [string]$sc.MaxMessageSize
                ProtocolLoggingLevel   = [string]$sc.ProtocolLoggingLevel
                Comment                = [string]$sc.Comment
                SendCount              = $sendCount
                FailCount              = $failCount
                LastUsed               = $lastUsed
                AuditStatus            = $auditStatus
                RecommendedAction      = $recommendedAction
            }
        } catch {
            Write-Host "  ! Ошибка обработки Send Connector $($sc.Name): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    $sendAuditFile = Join-Path $OutDir 'SendConnector-Audit.csv'
    $sendAudit | Sort-Object Name | Export-Csv -Path $sendAuditFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $sendAuditFile

    Write-Stage "Сбор Receive Connectors"
    $receiveConnectors = @(Get-ReceiveConnector)
    $receiveAudit = @()

    foreach ($rc in $receiveConnectors) {
        try {
            $rcIdentity = [string]$rc.Identity
            $rcTracking = @($rawTracking | Where-Object {
                $_.ConnectorId -and (
                    $_.ConnectorId -like "*$rcIdentity*" -or
                    $_.ConnectorId -like "*$($rc.Name)*"
                )
            })

            $receiveCount = @($rcTracking | Where-Object { $_.EventId -eq 'RECEIVE' }).Count
            $lastUsed = ($rcTracking | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
            $uniqueClientIps = @($rcTracking | Where-Object { $_.ClientIp } | Select-Object -ExpandProperty ClientIp -Unique)

            $permGroups = Join-ExchangeArray -Value $rc.PermissionGroups
            $isAnonymous = $permGroups -match 'AnonymousUsers'
            $isWideOpen = Test-IpRangeIsWideOpen -Ranges $rc.RemoteIPRanges

            $risk = 'Normal'
            if ($isAnonymous -and $isWideOpen) {
                $risk = 'HighRisk_AnonymousWideOpen'
            } elseif ($isAnonymous) {
                $risk = 'Check_AnonymousAllowed'
            }

            $auditStatus = if ($receiveCount -gt 0) { 'Used' } else { 'NoUsageFound_CandidateForReview' }
            $recommendedAction = if ($receiveCount -gt 0) {
                'Keep; monitor usage and permission scope.'
            } else {
                'No RECEIVE usage found; verify if still required.'
            }

            if ($isAnonymous) {
                $reviewCandidates += [PSCustomObject]@{
                    ObjectType        = 'ReceiveConnector'
                    Name              = [string]$rc.Name
                    Status            = 'AnonymousUsersAllowed'
                    Risk              = $risk
                    Details           = "PermissionGroups=$permGroups; RemoteIPRanges=$(Join-ExchangeArray -Value $rc.RemoteIPRanges)"
                    RecommendedAction = 'Validate relay purpose, scope, and source IP restrictions.'
                }
            }

            if ($auditStatus -eq 'NoUsageFound_CandidateForReview') {
                $reviewCandidates += [PSCustomObject]@{
                    ObjectType        = 'ReceiveConnector'
                    Name              = [string]$rc.Name
                    Status            = $auditStatus
                    Risk              = $risk
                    Details           = "No RECEIVE events in last $DaysBack days"
                    RecommendedAction = $recommendedAction
                }
            }

            $receiveAudit += [PSCustomObject]@{
                Identity             = $rcIdentity
                Name                 = [string]$rc.Name
                Server               = [string]$rc.Server
                Enabled              = $rc.Enabled
                Bindings             = (Join-ExchangeArray -Value $rc.Bindings)
                RemoteIPRanges       = (Join-ExchangeArray -Value $rc.RemoteIPRanges)
                AuthMechanism        = (Join-ExchangeArray -Value $rc.AuthMechanism)
                PermissionGroups     = $permGroups
                TransportRole        = [string]$rc.TransportRole
                MaxMessageSize       = [string]$rc.MaxMessageSize
                ProtocolLoggingLevel = [string]$rc.ProtocolLoggingLevel
                ReceiveCount         = $receiveCount
                LastUsed             = $lastUsed
                UniqueClientIps      = ($uniqueClientIps -join ';')
                Risk                 = $risk
                AuditStatus          = $auditStatus
                RecommendedAction    = $recommendedAction
            }
        } catch {
            Write-Host "  ! Ошибка обработки Receive Connector $($rc.Identity): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    $receiveAuditFile = Join-Path $OutDir 'ReceiveConnector-Audit.csv'
    $receiveAudit | Sort-Object Identity | Export-Csv -Path $receiveAuditFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $receiveAuditFile

    Write-Stage "Сбор Accepted Domains"
    $acceptedDomains = @(Get-AcceptedDomain | Select-Object Name,DomainName,DomainType,Default,MatchSubDomains,OutboundOnly)
    $acceptedDomainsFile = Join-Path $OutDir 'AcceptedDomains.csv'
    $acceptedDomains | Export-Csv -Path $acceptedDomainsFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $acceptedDomainsFile

    Write-Stage "Сбор Remote Domains"
    $remoteDomains = @(Get-RemoteDomain | Select-Object Name,DomainName,AllowedOOFType,AutoReplyEnabled,AutoForwardEnabled,DeliveryReportEnabled,TNEFEnabled,NDREnabled)
    $remoteDomainsFile = Join-Path $OutDir 'RemoteDomains.csv'
    $remoteDomains | Export-Csv -Path $remoteDomainsFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $remoteDomainsFile

    Write-Stage "Сбор Transport Rules"
    $transportRules = @(Get-TransportRule | Select-Object Name,State,Mode,Priority,Description)
    $transportRulesFile = Join-Path $OutDir 'TransportRules.csv'
    $transportRules | Export-Csv -Path $transportRulesFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $transportRulesFile

    Write-Stage "Формирование summary по использованию коннекторов"
    $connectorUsageSummary = @(
        $sendAudit | Select-Object @{n='ConnectorType';e={'Send'}},Name,SendCount,FailCount,LastUsed,AuditStatus,RecommendedAction
        $receiveAudit | Select-Object @{n='ConnectorType';e={'Receive'}},Name,@{n='SendCount';e={$null}},@{n='FailCount';e={$null}},LastUsed,AuditStatus,RecommendedAction
    )
    $connectorUsageSummaryFile = Join-Path $OutDir 'ConnectorUsage-Summary.csv'
    $connectorUsageSummary | Export-Csv -Path $connectorUsageSummaryFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $connectorUsageSummaryFile

    Write-Stage "DNS/TCP аудит SMTP endpoints"
    $dnsTargets = @()

    foreach ($s in $sendConnectors) {
        foreach ($as in $s.AddressSpaces) {
            $dnsTargets += [PSCustomObject]@{ SourceType = 'SendConnector.AddressSpace'; SourceObject = [string]$s.Name; Endpoint = [string]$as }
        }
        foreach ($sh in $s.SmartHosts) {
            $dnsTargets += [PSCustomObject]@{ SourceType = 'SendConnector.SmartHost'; SourceObject = [string]$s.Name; Endpoint = [string]$sh }
        }
    }

    foreach ($ad in $acceptedDomains) {
        $dnsTargets += [PSCustomObject]@{ SourceType = 'AcceptedDomain'; SourceObject = [string]$ad.Name; Endpoint = [string]$ad.DomainName }
    }

    $dnsTargets = @($dnsTargets | Where-Object { $_.Endpoint } | Sort-Object SourceType,SourceObject,Endpoint -Unique)
    $dnsTcpAudit = Invoke-DnsTcpAudit -Endpoints $dnsTargets

    $dnsTcpFile = Join-Path $OutDir 'DnsTcp-Audit.csv'
    $dnsTcpAudit | Export-Csv -Path $dnsTcpFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $dnsTcpFile

    foreach ($item in ($dnsTcpAudit | Where-Object { $_.Status -eq 'IssueDetected' })) {
        $reviewCandidates += [PSCustomObject]@{
            ObjectType        = 'DnsTcpEndpoint'
            Name              = "$($item.SourceObject)::$($item.NormalizedValue)"
            Status            = 'DnsOrTcpIssue'
            Risk              = 'Medium'
            Details           = "DnsResolved=$($item.DnsResolved); Tcp25ToEndpoint=$($item.Tcp25ToEndpoint); MxTcp25Summary=$($item.MxTcp25Summary); Errors=$($item.Errors)"
            RecommendedAction = 'Validate DNS records/firewall/routing and external endpoint availability.'
        }
    }

    $reviewCandidatesFile = Join-Path $OutDir 'ReviewCandidates.csv'
    $reviewCandidates | Sort-Object ObjectType,Name,Status -Unique | Export-Csv -Path $reviewCandidatesFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $reviewCandidatesFile

    $summary = [PSCustomObject]@{
        GeneratedAt               = Get-Date
        DaysBack                  = $DaysBack
        StartDate                 = $startDate
        EndDate                   = $endDate
        SendConnectorCount        = $sendConnectors.Count
        ReceiveConnectorCount     = $receiveConnectors.Count
        MessageTrackingRecordCount= $rawTracking.Count
        ReviewCandidateCount      = @($reviewCandidates | Sort-Object ObjectType,Name,Status -Unique).Count
        DnsTcpEndpointCount       = $dnsTcpAudit.Count
        DnsTcpUnavailableCount    = @($dnsTcpAudit | Where-Object { $_.Status -eq 'IssueDetected' }).Count
        ReportFolder              = $OutDir
    }

    $summaryFile = Join-Path $OutDir 'Summary.csv'
    $summary | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8
    $reportFiles += $summaryFile

    Write-Stage 'Аудит завершен. Созданные файлы:'
    $reportFiles | ForEach-Object { Write-Host " - $_" -ForegroundColor Green }

    Write-Host ''
    Write-Host 'Краткая сводка:' -ForegroundColor Cyan
    Write-Host " Send Connectors          : $($sendConnectors.Count)"
    Write-Host " Receive Connectors       : $($receiveConnectors.Count)"
    Write-Host " MessageTracking Records  : $($rawTracking.Count)"
    Write-Host " DNS/TCP Endpoints        : $($dnsTcpAudit.Count)"
    Write-Host " Review Candidates        : $(@($reviewCandidates | Sort-Object ObjectType,Name,Status -Unique).Count)"
    Write-Host " Report Folder            : $OutDir"
}
catch {
    Write-Host "Критическая ошибка выполнения аудита: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
