function Get-RSDeviceDetail {
    <#
    .SYNOPSIS
        Parses device XML
    .PARAMETER DeviceXML
        RedSeal Device XML GET response
    .OUTPUTS
        One custom object
#>
    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        $DeviceDetailXml
    )

    begin {
    }

    process {

        Write-Verbose "Fetching configuration object."
        $uri = $deviceDetailXml.Configuration.URL
        #$configXML = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $configXML = Send-RSRequest -uri $uri

        Write-Debug "Configuration XML is at configXml.innerxml"
    
        [pscustomobject] @{TreeID = $deviceDetailXml.TreeID
                DeviceName = $deviceDetailXml.Name
                LastModifiedDate = ConvertFrom-RSDate $deviceDetailXml.LastModifiedDate
                LastConfigModifiedDate = ConvertFrom-RSDate $deviceDetailXml.LastConfigModifiedDate
                PrimaryCapability = $deviceDetailXml.PrimaryCapability
                ParserWarnings = ($configXML.Configuration |select -ExpandProperty ParserWarnings)
        }
    }
}
