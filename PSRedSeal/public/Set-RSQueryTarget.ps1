function Set-RSQueryTarget {
    <#
    .SYNOPSIS
        Creates a target object for consumption by Invoke-RSQuery
    .PARAMETER Type
        Type of query target to create
    .PARAMETER TreeID
        TreeID to target
    .PARAMETER Ports
        Ports to target
    .PARAMETER Protocols
        Protocols to target
    .PARAMETER PATH
        GroupPath to target
    .OUTPUTS
        A single target object
#>
    [cmdletbinding(SupportsShouldProcess = $true, DefaultParametersetName="empty")]
    Param(
        [ValidateSet("Subnet", "Host", "Group", "AllTrusted", "AllUntrusted", "AllSubnets", "Device")]
        [string]
        $Type,

        [Parameter(ParameterSetName = "TreeID", mandatory = $true, ValueFromPipeline = $True)]
        [string]
        $TreeID,

        [Parameter()]
        [string]
        $IPs = "ANY",

        [Parameter()]
        [string]
        $Ports = "ANY",
        
        [Parameter()]
        [string]
        $Protocols = "ANY",
        
        [Parameter(ParameterSetName = "Group", mandatory = $true)]
        [string]
        $Path
    )

    begin {
    }

    process {

        #types can be AllSubnets (default), AllTrustedSubnets, AllUntrustedSubnets, Device, 
        #Host, Group, or Subnet

        switch ($type) {
            "Subnet" { $targetType = "Subnet"
                $targetID = $treeID }
            "Host" {
                $targetType = "Host"
                $targetID = $treeID }
            "Group" {
                $targetType = "Group"
                $targetID = $path }
            "Device" {
                $targetType = "Device"
                $targetID = $treeID }
            "AllTrusted" {
                $targetType = "AllTrustedSubnets"
                $targetID = "" }
            "AllUntrusted" {
                $targetType = "AllUntrustedSubnets"
                $targetID = "" }
            default {
                $targetType = "AllSubnets"
                $targetID = "" }
        }

        [PSCustomObject]@{
            Type      = $targetType
            ID        = $targetID
            IPs       = $IPs
            Ports     = $ports
            Protocols = $protocols
        }
    }
}
