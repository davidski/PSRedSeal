function New-RSHost {
    <#
    .SYNOPSIS
        Creates a new Host custom object. To post to RedSeal, send the object to Set-RSHost
    .OUTPUTS
        One custom object
#>
    [cmdletbinding(SupportsShouldProcess = $true)]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        $HostName,

        [Parameter(Mandatory = $false)]
        $SpecifiedValue,

        [Parameter(Mandatory = $false)]
        $IPAddress,

        [Parameter(Mandatory = $false)]
        $Comments
    )

    begin {
    }

    process {

        [pscustomobject] @{
                TreeID           = $null
                Hostname         = $HostName
                SpecifiedValue   = if ($SpecifiedValue) { $SpecifiedValue } else { $null }
                IPAddress        = $IPAddress
                Comments         = $Comments
        }
    }
}
