function Get-RSHost {
    <#
    .SYNOPSIS
        Get info on a given host
    .PARAMETER TreeID
        RedSeal TreeID for a host object
    .PARAMETER Name
        DNS name of the host object
    .PARAMETER FetchAll
        Fetches all host defined on the RedSeal server. Returns only the name, URL, and TreeID of hosts.
    .PARAMETER NoMetrics
        Do not fetch the metrics data.
    .OUTPUTS
        One custom object per host.
#>
    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID="2c9697a7316371660131f73d53b2593a",

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name="ppwsec05.childrens.sea.kids",

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'FetchAll')]
        [Switch]
        $FetchAll = $False,

        [Parameter(ValueFromPipeline = $true, Mandatory = $false)]
        [Switch]
        $NoMetrics = $False
            
    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/host/$Name"
        } elseif ($PSCmdlet.ParameterSetName -eq 'FetchAll') {
            $uri = "https://$script:server/data/host/all"
        } else {
            $uri = "https://$script:server/data/host/id/$TreeID"
        }
        
        Write-Verbose "Fetching host object(s)."   
        #$hostXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $hostXml = Send-RSRequest -uri $uri

        Write-Debug "XML returned is at hostXml.innerXML"

        if ($hostXml.message.text -like 'No host*') {
            [pscustomobject] @{Message = "No host found"}
        } elseif ($hostXml.list -and -!$FetchAll) {
            $hostXml.list.host | foreach { 
                if ($NoMetrics -or !$_.metrics) {
                    [pscustomobject] @{
                        TreeID           = $_.TreeID
                        Hostname         = $_.Name
                        IPAddress        = $_.Interfaces.Interface.Address
                        OperatingSystem  = $_.OperatingSystem
                        SpecifiedValue   = if ($_.Value) { [int]$_.Value } else { $null }
                        Applications     = $_.Applications
                        LastModifiedDate = ConvertFrom-RSDate $_.LastModifiedDate
                        LastScannedDate  = if ($_.LastScannedDate) { ConvertFrom-RSDate $_.LastScannedDate } else { $null }
                        HostType         = $_.Type
                        PrimaryCapability = "HOST"
                        Comments         = $_.Comments
                     }
                } else {
                    Get-RSHostDetail $_ 
                }
            }
        } elseif ($FetchAll) {
            $hostXml.list.host | foreach {
                [pscustomobject] @{
                    Hostname   = $_.name
                    URL    = $_.URL
                    TreeID = $_.TreeID
                    PrimaryCapability = "HOST"
                }
            }
        } else {
            if ($NoMetrics -or !$hostxml.host.metrics) {
                $hostxml.host | foreach {
                    [pscustomobject] @{
                        TreeID           = $_.TreeID
                        Hostname         = $_.Name
                        IPAddress        = $_.Interfaces.Interface.Address
                        OperatingSystem  = $_.OperatingSystem
                        SpecifiedValue   = if ($_.Value) { [int]$_.Value } else { $null }
                        Applications     = $_.Applications
                        LastModifiedDate = ConvertFrom-RSDate $_.LastModifiedDate
                        LastScannedDate  = if ($_.LastScannedDate) { ConvertFrom-RSDate $_.LastScannedDate } else { $null }
                        HostType         = $_.Type
                        PrimaryCapability = "HOST"
                        Comments         = $_.Comments
                    }
                }
            } else {
                Get-RSHostDetail $hostXML.host
            }
        }
          
    }
}
