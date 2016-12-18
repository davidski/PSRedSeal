function New-RSGroup {
    <#
    .SYNOPSIS
        Creates a new group custom object. To post to RedSeal, send the object to Set-RSGroup
    .PARAMETER GroupName
        Name of the top level group
    .PARAMETER GroupPath
        RedSeal path to the top level group
    .PARAMETER References
        Hash of Name, URL, Path, TargetName, TargetURL, TargetPath to any desired reference group
    .PARAMETER Hosts
        Array of hosts to add to the group membership
    .PARAMETER Comments
        Text to place into the RedSeal group comments field
    .OUTPUTS
        One custom object
#>
    [cmdletbinding(SupportsShouldProcess = $true)]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        $GroupName,

        [Parameter(Mandatory = $false)]
        $GroupPath,

        [Parameter(Mandatory = $false)]
        $IPAddress,

        [Parameter(Mandatory = $false)]
        $Comments,

        [Parameter(Mandatory = $false)]
        $Hosts,

        [Parameter(Mandatory = $false)]
        $References
    )

    begin {
    }

    process {

        [pscustomobject] @{
                GroupName        = $GroupName
                GroupPath        = $GroupPath
                Comments         = if ($Comments) { $Comments } else { $null }
                Hosts            = if ($Hosts)   { $Hosts   } else { $null }
                Subnets          = if ($Subnets) { $Subnets } else { $null }
                Devices          = if ($Devices) { $Devices } else { $null }
                References       = if ($References) { $References } else { $null }
        }
    }
}
