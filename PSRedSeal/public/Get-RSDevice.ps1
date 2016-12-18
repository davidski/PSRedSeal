function Get-RSDevice {
    <#
    .SYNOPSIS
        Get info on a given device
    .PARAMETER TreeID
        RedSeal TreeID for a device object
    .PARAMETER Name
        DNS name of the device object
    .OUTPUTS
        One custom object per device.
#>
    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]$TreeID="2c9697a7316371660131f73d53b2593a",

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name="871-Kent"
            
    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/device/$Name"
        } else {
            $uri = "https://$script:server/data/device/id/$TreeID"
        }
        
        Write-Verbose "Fetching device object."   
        #$deviceXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $deviceXml = Send-RSRequest -uri $uri

        Write-Debug "XML returned is at deviceXml.innerXML"

        if ($deviceXml.message.text -like 'No Device found*') {
            [pscustomobject] @{Message = "No device found"}
        } elseif ($deviceXml.list) {
            $deviceXml.list.device | foreach { Get-RSDeviceDetail $_ }
        } else {
            Get-RSDeviceDetail $deviceXml.device   
        }
    }
}
