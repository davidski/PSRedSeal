function Get-RSHostDetail {
    <#
    .SYNOPSIS
        Parses host XML to return host and metrics data
    .PARAMETER HostDetailXML
        RedSeal Host Detail XML GET response
    .OUTPUTS
        One custom object
#>
    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        $HostDetailXml
    )

    begin {
    }

    process {

        Write-Verbose "Fetching metrics object."
        $uri = $hostDetailXml.Metrics.URL
        #$metricsXML = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $metricsXML = Send-RSRequest -uri $uri
        Write-Debug "Metrics XML is at metricsXml.innerxml"
        
        [pscustomobject] @{
                TreeID           = $hostDetailXml.TreeID
                Hostname         = $hostDetailXml.Name
                IPAddress        = $hostDetailXml.Interfaces.Interface.Address
                OperatingSystem  = $hostDetailXml.OperatingSystem
                Value            = [int]$metricsXML.Metrics.Value
                SpecifiedValue   = if ($hostDetailXml.Value) { [int]$hostdetailXML.Value } else { $null }
                AttackDepth      = [int]$metricsXML.Metrics.AttackDepth
                Exposure         = $metricsXML.Metrics.Exposure
                Risk             = [int]$metricsXML.Metrics.Risk
                DownstreamRisk   = [int]$metricsXML.Metrics.DownstreamRisk
                Leapfroggable    = [System.Convert]::ToBoolean($metricsXML.Metrics.Leapfroggable)
                Exploitable      = [System.Convert]::ToBoolean($metricsXML.Metrics.Exploitable)
                Applications     = $HostDetailXml.Applications
                LastModifiedDate = ConvertFrom-RSDate $hostDetailXml.LastModifiedDate
                LastScannedDate  = if ($hostDetailXML.LastScannedDate) { ConvertFrom-RSDate $hostDetailXml.LastScannedDate } else { $null }
                HostType         = $hostDetailXml.Type
                PrimaryCapability = "HOST"
                Comments         = $hostDetailXml.Comments
        }
    }
}
