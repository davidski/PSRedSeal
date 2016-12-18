function Set-RSHost {
    <#
    .SYNOPSIS
        Update a host object on RedSeal
    .PARAMETER HostObject
        Host object to update. May be an array of hosts.
    .PARAMETER XML
        Display generated XML, but do not post
    .INPUTS
        Full host object.
    .OUTPUTS
        One result object.
#>

    [cmdletbinding(SupportsShouldProcess = $true)]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [PSCustomObject[]]
        $HostObject,

        [Parameter(Mandatory = $false)]
        [switch]
        $XML = $false

    )

    begin {
        if ($null -eq $Credentials) {
            Connect-RSServer
        }
    }

    process {

        $hostXml = New-Object XML
        $decl = $hostXml.CreateXmlDeclaration("1.0", $null, $null)
        $decl.Encoding = "ISO-8859-1"
        $e = $hostxml.CreateElement("Host")
        $hostXml.InsertBefore($decl, $hostXml.DocumentElement) | Out-Null
        $hostXml.AppendChild($e) | Out-Null
        
        #create a processing directive for the mandatory header
        $pi = $hostXml.CreateProcessingInstruction("RedSeal", 'mediaType="application/x-RedSealv5.0+xml"')
        $hostXml.InsertBefore($pi, $hostXml.ChildNodes[1]) | Out-Null

        foreach ($singleHost in $HostObject) {
            
            $e = $hostXml.CreateElement("Name")
            $e.InnerText = $singleHost.hostname
            $hostXml.SelectSingleNode("/Host[last()]").AppendChild($e) | Out-Null
            
            #set host value, if specified
            if ($singleHost.SpecifiedValue) {
                $e = $hostXml.CreateElement("Value")
                $e.InnerText = $singleHost.SpecifiedValue
                $hostXml.SelectSingleNode("/Host[last()]").AppendChild($e) | Out-Null
            }
            
            $e = $hostXml.CreateElement("Interfaces")
            $hostXml.SelectSingleNode("/Host[last()]").AppendChild($e) | Out-Null
            
            #foreach interface (only support 1 interface in this iteration)
            $e = $hostXml.CreateElement("Interface")
            $hostXml.SelectSingleNode("/Host/Interfaces[last()]").AppendChild($e) | Out-Null
            $e = $hostXml.CreateElement("Address")
            $e.InnerText = $singleHost.IPAddress
            $hostXml.SelectSingleNode("/Host/Interfaces/Interface[last()]").AppendChild($e) | Out-Null
            
            $e = $hostXml.CreateElement("Applications")
            $hostXml.SelectSingleNode("/Host[last()]").AppendChild($e) | Out-Null
            
            #foreach application
            <#
            
            $e = $hostXml.CreateElement("Applications")
            $e.InnerText = <appname>
            $hostXml.SelectSingleNode("/Host/Applications[last()").AppendChild($e) | Out-Null
            
            $e = $hostXml.CreateElement("IP")
            $e.InnerText = <appIP>
            $hostXml.AppendChild($e) | Out-Null
            
            #ports and protocols
            $e = $hostXml.CreateElement("PortAndProtocol")
            $e.InnerText = <appname>
            $hostXml.AppendChild($e) | Out-Null
            
            $interface.address.innertext() = $host.Address
            $applications
            $application.IP
            $application.portandprotocol
            $application.portandprotocol.port
            $application.portandprotocol.protocol
            
            #vulnerabilities
            $application.vulnerabilities
            #>

            #set the host comments (aka Description)
            $e = $hostXml.CreateElement("Comments")
            $e.InnerText = $singleHost.Comments
            $hostXml.SelectSingleNode("/Host[last()]").AppendChild($e) | Out-Null

        }

        $respbody = $($hostXml.InnerXML.ToString().Replace("><",">`r`n<"))

        #post the updated XML
        if ($XML) {
            $respBody
        } else {
            $uri = "https://" + $script:server + "/data/host"
            $result = Send-RSRequest -uri $uri -Method POST -Body $respbody
            #$result = Invoke-RestMethod -uri $uri -Credential $script:credentials -method Post -ContentType "multipart/form-data" -Body $respBody
            
            #parse response
            Write-Debug "Response is $result"
            
            [pscustomobject]@{
                Status      = $result.ImportResult.Status
                StartTime   = $result.ImportResult.StartTime
                ExecutionMS = $result.ImportResult.ExecutionMS
                Notes       = $result.ImportResult.Notes
                Details     = $result.ImportResult.Details
            }
        }
    }
}
