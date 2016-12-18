function Invoke-RSQuery {
    <#
    .SYNOPSIS
        Invokes a synchronous RedSeal query
    .OUTPUTS
        One or more query result pairs
    .PARAMETER SourceSubnet
        Source subnet for detailed queries
    .PARAMETER DestinationSUbnet
        Destination subnet for detailed queries
    .PARAMETER DestinationIPs
        Destination IPs
    .PARAMETER SourceIPs
        Source IPs
    .PARAMETER QueryType
        Either Access, Threat, Impact, or Path query type. Defaults to access.
    .PARAMETER XML
        Switch flag (T/F) to indicate returning raw XML is desired instead of parsed objects
#>
    [cmdletbinding(DefaultParameterSetName='DetailedQuery')]
    Param(
        [Parameter(ParameterSetName='DetailedQuery', Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [String]
        $SourceSubnet = "4028aa8f2f63ce90012f63d85f6600de",

        [Parameter(ParameterSetName='DetailedQuery', Mandatory = $false, valueFromPipeline = $true, Position = 1)]
        [String]
        $DestinationSubnet = $null,

        [Parameter(ParameterSetName = 'DetailedQuery', Mandatory = $false)]
        [String]
        $SourceIPs,

        [Parameter(ParameterSetName = 'DetailedQuery', Mandatory = $false)]
        [String]
        $DestinationIPs,

        [Parameter(ParameterSetName = 'TargetObject', Mandatory = $false, valueFromPipeline = $true, Position = 1)]
        [PSCustomObject[]]
        $SourceTarget,

        [Parameter(ParameterSetName = 'TargetObject', Mandatory = $false, valueFromPipeline = $true, Position = 2)]
        [PSCustomObject[]]
        $DestinationTarget,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Access', 'Threat', 'Path', 'Impact')]
        [String]
        $QueryType = "Access",

        [Parameter(Mandatory = $false)]
        [Switch]
        $XML,

        [Parameter(Mandatory = $false)]
        [Int]
        $TimeoutSec = 60*6

    )

    begin {
   
        $uriPath = switch ($QueryType.ToLower()) {
            "Access" {"access"}
            "Threat" {"threats"}
            "Impact" {"impact"}
            "Path" {"path"}
            default {"access"}
        }

    }

    process {

        $accessXml = New-Object XML
        $e = $accessxml.CreateElement("Query")
        $accessXml.AppendChild($e) | Out-Null
        $e = $accessxml.CreateElement("Name")
        $e.innertext = "RS PoSH Query"
        $accessXml.SelectSingleNode("/Query").AppendChild($e) | Out-Null

        switch ($PSCmdlet.ParameterSetName) {
            'DetailedQuery' {
                $accessXml.Query.Sources.Targets.target.type="Subnet"
                #if ($PSBoundParameters.ContainsKey("SourceSubnet")) {
                    $accessXml.Query.Sources.Targets.target.id = $SourceSubnet
                #} else {
                    #$accessXml.Query.Sources.Targets.target.id = ""
                #}
                if ($PSBoundParameters.ContainsKey("SourceIPs")) {
                    $accessXml.Query.Sources.IPs = $SourceIPs
                } else {
                    $accessXml.Query.Sources.IPs = ""
                }
        
                $accessXml.Query.Sources.Restrict = "NONE"

                $accessXml.Query.Destinations.Targets.target.type="AllSubnets"
                if ($PSBoundParameters.ContainsKey("Destinationubnet")) {
                    $accessXml.Query.Destinations.Targets.target.id = $DestinationSubnet
                } else {
                    $accessXml.Query.Destinations.Targets.target.id = ""
                }
                if ($PSBoundParameters.ContainsKey("DestinationIPs")) {
                    $accessXml.Query.Destinations.IPs = $DestinationIPs
                } else {
                    $accessXml.Query.Destinations.IPs = ""
                }
                $accessXml.Query.Destinations.Restrict = "NONE"
            }
            'TargetObject' {
               

                $e = $accessXml.CreateElement("Protocol")
                $e.InnerText = $DestinationTarget.Protocols
                $accessXml.SelectSingleNode("/Query").AppendChild($e) | Out-Null

                #Create source targets XML stanzas
                $e = $accessXml.CreateElement("Sources")
                $accessXml.SelectSingleNode("/Query").AppendChild($e) | Out-Null

                $e = $accessXml.CreateElement("Targets")
                $accessXml.SelectSingleNode("/Query/Sources").AppendChild($e) | Out-Null

                foreach ($s in $SourceTarget) {
                    $e = $accessXml.CreateElement("Target")
                    $accessXml.Query.SelectSingleNode("/Query/Sources/Targets[last()]").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("Type")
                    $e.InnerText = $s.Type

                    $accessXml.SelectSingleNode("/Query/Sources/Targets/Target[last()]").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("ID")
                    $e.InnerText = $s.id

                    $accessXml.SelectSingleNode("/Query/Sources/Targets/Target[last()]").AppendChild($e) | Out-Null

                }

                #set source clause specific options
                $e = $accessXml.CreateElement("IPs")
                $e.InnerText = $sourceTarget.IPs | Sort | Unique
                $accessXml.SelectSingleNode("/Query/Sources").AppendChild($e) | Out-Null

                $e = $accessXml.CreateElement("Restrict")
                $e.InnerText = "NONE"
                $accessXml.SelectSingleNode("/Query/Sources").AppendChild($e) | Out-Null

                #Create Destination targets
                $e = $accessXml.CreateElement("Destinations")
                $accessXml.SelectSingleNode("/Query").AppendChild($e) | Out-Null

                $e = $accessXml.CreateElement("Targets")
                $accessXml.SelectSingleNode("/Query/Destinations").AppendChild($e) | Out-Null

                foreach ($d in $destinationTarget) {

                    $e = $accessXml.CreateElement("Target")
                    $accessXml.SelectSingleNode("/Query/Destinations/Targets[last()]").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("ID")
                    $e.InnerText = $d.id

                    $accessXml.SelectSingleNode("/Query/Destinations/Targets/Target[last()]").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("Type")
                    $e.InnerText = $d.Type

                    $accessXml.SelectSingleNode("/Query/Destinations/Targets/Target[last()]").AppendChild($e) | Out-Null
                }

                #set destination clause specific options
                $e = $accessXml.CreateElement("Ports")
                $e.InnerText = $DestinationTarget.Ports
                $accessXml.SelectSingleNode("/Query/Destinations").AppendChild($e) | Out-Null

                $e = $accessXml.CreateElement("IPs")
                $e.InnerText = $DestinationTarget.IPs
                $accessXml.SelectSingleNode("/Query/Destinations").AppendChild($e) | Out-Null

                $e = $accessXml.CreateElement("Restrict")
                $e.InnerText = "NONE"
                $accessXml.SelectSingleNode("/Query/Destinations").AppendChild($e) | Out-Null

            }
        }

        #set the body of the HTTP put
        $respBody = $($accessXml.InnerXML.ToString().Replace("><",">`r`n<"))

        Write-Verbose "Query put body is: $respBody"
        
        $uri = "https://$script:server/data/$uripath"
        Write-Verbose "URI is $uri"

        #finally, try to execute the query
        try {
            #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -Method Put -Body $respBody -TimeoutSec $timeoutSec -DisableKeepAlive
            $resultXml = Send-RSRequest -uri $uri -Method Put -Body $respBody -TimeoutSec $timeoutSec
        }
        catch {
            throw $_.Exception.Message
        }

        Write-Debug $resultXml.innerxml.tostring()        

        if ($XML) {
            $resultXml
        } else {

            switch ($QueryType) {
                "Access" {
                    Read-RSAccessResult -RawXML $resultXml
                }
                "Threat" { 
                    Read-RSThreatResult -RawXML $resultXml
                }
                "Path" { 
                    Read-RSPathResult -RawXML $resultXml
                }
                "Impact" { 
                    Read-RSImpactResult -RawXML $resultXml 
                }
            }
        }
    }
}
