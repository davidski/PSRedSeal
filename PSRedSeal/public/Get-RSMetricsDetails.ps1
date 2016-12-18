function Get-RSMetricsDetail {
<#
    .SYNOPSIS
        Internal function for parsing DataQuery results objects into host objects
    .INPUT
        Expects one metrics object and the path to that object
    .OUTPUTS
        Returns one host metrics object for each metrics result
#>
    [cmdletbinding()]
    Param(
        [Parameter(mandatory = $true)]
        $QueryLeaf,

        [Parameter()]
        $GroupPath

    )

    begin {
    }

    process {
        [pscustomobject]@{
            Name           = $QueryLeaf.Name
            GroupPath      = $GroupPath
            TreeID         = $QueryLeaf.TreeID
            AnalysisDate   = ConvertFrom-RSDate $QueryLeaf.AnalysisDate
            PrimaryService = $QueryLeaf.PrimaryService
            Vendor         = $QueryLeaf.Vendor
            OS             = $QueryLeaf.OS
            AttackDepth    = $QueryLeaf.AttackDepth
            Exposure       = $QueryLeaf.Exposure
            Value          = $QueryLeaf.Value
            ServicesCount  = $QueryLeaf.ServicesCount
            VulnerabilityCount = $QueryLeaf.VulnerabilityCount
            Risk           = $QueryLeaf.Risk
            DownstreamRisk = $QueryLeaf.DownstreamRisk
            Confidence     = $QueryLeaf.Confidence
            Leapfroggable  = [boolean]$QueryLeaf.Leapfroggable
            Exploitable    = [boolean]$QueryLeaf.Exploitable
            PrimaryIP      = $QueryLeaf.PrimaryIP
            AccessibleFromUntrusted = [boolean]$QueryLeaf.AccessibleFromUntrusted
            HasAccesstoCritical = [boolean]$QueryLeaf.HasAccessToCritical
        }
    }
}
