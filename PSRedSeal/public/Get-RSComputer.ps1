function Get-RSComputer {
    <#
    .SYNOPSIS
        Get info on a given host or device using the generic RedSeal computer call
    .PARAMETER TreeID
        RedSeal TreeID for a host or device object
    .PARAMETER Name
        DNS name of the computer object
    .PARAMETER FetchAll
        Fetches all computers defined on the RedSeal server. Returns only hostname, url, treeID, and primary capability.
    .OUTPUTS
        One custom object per computer/device.
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
        $FetchAll = $False
          
    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/computer/$Name"
        } elseif ($PSCmdlet.ParameterSetName -eq 'FetchAll') {
            $uri = "https://$script:server/data/computer/*"
        } else {
            $uri = "https://$script:server/data/computer/$TreeID"
        }
        
        Write-Verbose "Fetching computer object(s)."
        #$hostXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $computerXml = Send-RSRequest -uri $uri

        Write-Debug "XML returned is at computerXml.innerXML"

        if ($computerXml.message.text -like 'No host*') {
            [pscustomobject] @{Message = "No computer found"}
        } elseif ($computerXML.host) {
            $computerXml.host | foreach {
                [pscustomobject] @{
                        TreeID           = $_.TreeID
                        Hostname         = $_.Name
                        IPAddress        = $_.Interfaces.Interface.Address
                        OperatingSystem  = $_.OperatingSystem
                        SpecifiedValue   = if ($_.Value) { [int]$_.Value } else { $null }
                        HostType             = $_.Type
                        Applications     = $_.Applications
                        LastModifiedDate = ConvertFrom-RSDate $_.LastModifiedDate
                        LastScannedDate  = if ($_.LastScannedDate) { ConvertFrom-RSDate $_.LastScannedDate } else { $null }
                        PrimaryCapability = "HOST"
                        Comments         = $_.Comments
                }
            }
        } elseif ($computerXML.Device) {
            $computerXml.device | foreach {
                [pscustomobject] @{
                    Hostname   = $_.name
                    URL    = $_.URL
                    TreeID = $_.TreeID
                    IPAddress        = $_.Interfaces.Interface | foreach { $_.address}
                    OperatingSystem  = $_.OperatingSystem
                    Applications     = $_.Applications
                    LastModifiedDate = ConvertFrom-RSDate $_.LastModifiedDate
                    LastImportedDate  = if ($_.LastImportedDate ) { ConvertFrom-RSDate $_.LastImportedDate } else { $null }
                    BestPractices    = $_.BestPractices
                    Configuration    = $_.Configuration
                    PrimaryCapability = $_.PrimaryCapability
                    Comments         = $_.Comments
                }
            }    
        } elseif ($computerXml.list) {
            $computerXml.list.host | foreach {
                [pscustomobject] @{
                    Hostname    = $_.Name
                    TreeID      = $_.TreeID
                    URL         = $_.URL
                    PrimaryCapability = "HOST"
                }
            }
            $computerXml.list.device | foreach {
                [pscustomobject] @{
                    Hostname   = $_.name
                    TreeID = $_.TreeID
                    URL    = $_.URL
                    PrimaryCapability = $_.PrimaryCapability
                }
            }
        }
    }
}
