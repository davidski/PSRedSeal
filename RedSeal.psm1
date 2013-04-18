#Author: David F. Severski
#Date: 10/28/2012
#Purpose: Expose the RedSeal API via PowerShell
#Bugs: Many...Just a POC
#don't yet support impact or detailed path queries
#modify the subnet queries to return host and device objects instead of unwound treeID/hostname, treeid/devicename lists

#default server name
$script:Server = "redseal.servername.local"

#default access query template
[xml]$script:queryTemplate = @"
<?xml version="1.0" encoding="ISO-8859-1" ?>
<Query>
  <Name>Query type</Name>
  <Protocol>any</Protocol>
</Query>
"@

function Connect-RSServer {
    <#
    .SYNOPSIS
        Set connection parameters for the RedSeal cmdlets
    .OUTPUTS
        None.
#>
    Param(
    
    [Parameter(Mandatory=$false, Position = 0)]
    [string]
    $Server,

    [Parameter(Mandatory=$false, Position = 1)]
    [PSCredential]
    $Credentials
    )

    if ($PSBoundParameters.ContainsKey("Server")) {
        $script:Server = $Server
    }

    #if a credential has not been pased or previously defined, mandate that one be specified
    if ($PSBoundParameters.ContainsKey("Credentials")) {
        $script:Credentials = $Credentials
    } elseif ($script:Credentials -isnot [pscredential]) {
        $script:Credentials = Get-Credential -Message "Enter credentials for the RedSeal server"
    }

}

function Get-RSConnection {
    [pscustomobject]@{
        Server = $script:Server
        Credentials = $script:Credentials
    }
}

function Get-RSSystemStatus {
    <#
    .SYNOPSIS
        Fetch the system status of the RedSeal Server
    .OUTPUTS
        A single system status object
#>

    begin {

        $uri = "https://" + $script:Server + "/data/system"

        $resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials

        [pscustomobject]@{
            LastAnalysisStatus = $resultXml.SystemStatus.LastAnalysis.Status
            LastAnalysisStartTime = $resultXml.SystemStatus.LastAnalysis.StartTime | ConvertFrom-RSDate
            LastAnalysisEndTime = $resultXml.SystemStatus.LastAnalysis.EndTime | ConvertFrom-RSDate
            RunningAnalysisStatus = $resultXml.SystemStatus.RunningAnalysis.Status
            RunningAnalysisStatusStartTime = $(if ($resultXml.SystemStatus.RunningAnalysis.StartTime -ne $null ) {
                ConvertFrom-RSDate $resultXml.SystemStatus.RunningAnalysis.StartTime
                })
            RunningAnalysisStatusPercentComplete = $resultXml.SystemStatus.RunningAnalysis.PercentComplete
            RunningAnalysisStatusStage = $resultXml.SystemStatus.RunningAnalysis.Name
            TRLVersion = $resultXml.SystemStatus.TRLVersion
        }
    }
}

function Set-RSQueryTarget {
    <#
    .SYNOPSIS
        Creates a target object for consumption by Invoke-RSQuery
    .OUTPUTS
        A single target object
#>
    [cmdletbinding(DefaultParametersetName="empty")]
    Param(
        [ValidateSet("Subnet", "Host", "Group", "AllTrusted", "AllUntrusted", "AllSubnets","Device")]
        [string]
        $Type,

        [Parameter(ParameterSetName = "TreeID", mandatory = $true)]
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
        
        [Parameter(ParameterSetName= "Group", mandatory = $true)]
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
                $targetID = ""
                }
            "AllUntrusted" {
                $targetType = "AllUntrustedSubnets"
                $targetID = ""
                }
            default {
                $targetType = "AllSubnets"
                $targetID = ""
                }

        }

        [PSCustomObject]@{
            Type = $targetType
            ID = $targetID
            IPs = $IPs
            Ports = $ports
            Protocols = $protocols
        }
    }
}

function Invoke-RSQuery {
    <#
    .SYNOPSIS
        Invokes a synchronous RedSeal query
    .OUTPUTS
        One or more query result pairs
    .PARAMETER QueryType
        Either Access, Threat, Impact, or Path query type. Defaults to access.
    .PARAMETER XML
        Switch flag (T/F) to indicate returning raw XML is desired instead of parsed objects
#>
    [cmdletbinding(DefaultParameterSetName='DetailedQuery')]
    Param(
        [Parameter(ParameterSetName='DetailedQuery', Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [String]
        $SourceSubnet = $null,

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

begin
    {
   
        $uriPath = switch ($QueryType.ToLower()) {
            "Access" {"access"}
            "Threat" {"threats"}
            "Impact" {"impact"}
            "Path" {"path"}
            default {"access"}
        }

    }

    process {

        #$accessXml = $script:queryTemplate
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
                    $accessXml.SelectSingleNode("/Query/Sources/Targets[last()]").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("Type")
                    $e.InnerText = $s.Type

                    $accessXml.SelectSingleNode("/Query/Sources/Targets[last()]/Target").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("ID")
                    $e.InnerText = $s.id

                    $accessXml.SelectSingleNode("/Query/Sources/Targets[last()]/Target").AppendChild($e) | Out-Null

                }

                #set source clause specific options
                $e = $accessXml.CreateElement("IPs")
                $e.InnerText = $sourceTarget.IPs
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

                    $accessXml.SelectSingleNode("/Query/Destinations/Targets[last()]/Target").AppendChild($e) | Out-Null

                    $e = $accessXml.CreateElement("Type")
                    $e.InnerText = $d.Type

                    $accessXml.SelectSingleNode("/Query/Destinations/Targets[last()]/Target").AppendChild($e) | Out-Null
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
            $resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -Method Put -Body $respBody -TimeoutSec $timeoutSec -DisableKeepAlive
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

function Read-RSAccessResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal access query
    .OUTPUTS
        One custom object per traffic segment
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [XML]
        $RawXML
    )

    begin {
    }
    
    process {

        Write-Verbose "RawXml is $($rawXml.innerxml.tostring())"

        $table = @{}

        if ($rawXml.AccessResults.Message.innertext -like "*No access found*") {
            $table.add("Status", "No access found.")
            return [pscustomobject] $table
        } elseif ($rawXml.AccessResults.Message -ne $null) {
            throw "No response found: $($rawXml.innerxml.tostring())"
        }

         $rawXml.AccessResults.TrafficSegment | % {
                
                $table = @{}
                $table.add("Status", "TrafficSegment")
                $table.add("Source", $_.Source)
                $table.add("Destination", $_.Destination)
                $table.add("Traffic", $_.Traffic)

                [pscustomobject] $table
         }
    }
}

function Read-RSThreatResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal threat query
    .OUTPUTS
        One custom object per traffic segment
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [XML]
        $RawXML
    )

    begin {
    }
    
    process {

        Write-Verbose "RawXml is $($rawXml.innerxml.tostring())"

        $table = @{}

        if ($rawXml.ThreatResults.Message.innertext -like "*No threats found*") {
            $table.add("Status", "No threats found.")
            return [pscustomobject] $table
        } elseif ($rawXml.ThreatResults.Message -ne $null) {
            throw "No response found: $($rawXml.innerxml.tostring())"
        }

         $rawXml.ThreatResults.ThreatSegment | % {
                
                $table = @{}
                $table.add("Status", "ThreatSegment")
                $table.add("Source", $_.Source)
                $table.add("Destination", $_.Destination)
                $table.add("Threat", $_.Threat)

                [pscustomobject] $table
         }
    }
}

function Read-RSImpactResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal impact query
    .OUTPUTS
        One custom object per traffic segment
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [XML]
        $RawXML
    )

    begin {
    }
    
    process {

        Write-Verbose "RawXml is $($rawXml.innerxml.tostring())"

        $table = @{}

        if ($rawXml.SecurityImpact.PathStatus -like "*No threats found*") {
            $table.add("Status", "No threats found.")
            return [pscustomobject] $table
        } #elseif ($rawXml.SecurityImpact.Message -ne $null) {
           # throw "No response found: $($rawXml.innerxml.tostring())"
        #}


        $rawXml.SecurityImpact | % {
        
            $table = @{}
            $table.add("Status", "Impact")
            $table.add("PathStatus", $_.PathStatus)
            $table.add("SourceAttackDepth", $_.SourceAttackDepth)
            $table.add("DestinationAttackDepth", $_.DestinationAttackDepth)
            $table.add("ExposedVulnerabilities", $_.ExposedVulnerabilities)
            $table.add("UniqueVulnerabilities", $_.Destination.UniqueVulnerabilities)
            $table.add("OldestScan", $(ConvertFrom-RSDate $_.Destination.OldestScan))
            $table.add("MaxCVSS", $_.Destination.MaxCVSS)
            $table.add("LeapFrog", $_.Destination.LeapFrog)
            $table.add("NumberOfHosts", $_.Destination.NUmberOfHosts)
            if ($table.LeapFrog -eq $true) {
                $table.add("ReachableHosts", $_.Destination.Destinations.LeapFrog)
            }

            [pscustomobject] $table
        }
    }
}

function Read-RSPathResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal detailed path query
    .OUTPUTS
        Still figuring that out...
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [XML]
        $RawXML
    )

    begin {
    }
    
    process {

        Write-Verbose "RawXml is $($rawXml.innerxml.tostring())"

        $table = @{}

        if ($rawXml.PathResult.Result.innertext -like "*CLOSED*") {
            $table.add("Status", "No open paths found.")
            return [pscustomobject] $table
        } elseif ($rawXml.PathResult.Message -ne $null) {
            throw "No response found: $($rawXml.innerxml.tostring())"
        }

        $rawXml.PathResult.Paths.Path | % {
                
            $table = @{}
            $table.add("Status", "PathSegment")
            $table.add("PathID", $_.PathID)
            $table.add("Hops", $_.Hops)

            [pscustomobject] $table
         }
    }
}

function ConvertFrom-RSDate {
    <#
    .SYNOPSIS
        Converts from RedSeal timezone date to a .NET datetime object
    .OUTPUTS
        A .NET datetime object
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [String]
        $RSDate
    )

    process {
        Write-Verbose "Received a raw date of $RSDate"

        if ($RSDate -ne $null) {
            $RSDate =  $RSDate -replace "\s\w{3}$", ""
            [datetime]::ParseExact($RSDate, "MMM d, yyyy h:mm:ss tt", $null)
        }

    }
}

function Get-RSView {
    <#
    .SYNOPSIS
        Get all available views in RedSeal
    .OUTPUTS
        One custom object per view
#>
    [cmdletbinding()]
    Param(      
    )
    
    begin {
    }

    process {

        $uri = "https://$script:Server/data/view"
        
        Write-Debug "Query URI is $uri"

        $viewXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"

        $viewXml.list.view | % {

            [pscustomobject] @{ViewName = $_.name
                URL = $_.url
                PolicyEnabled = $_.policyEnabled
                Comments = $_.comments
            }
        }
    }
}

function Get-RSGroup {
    <#
    .SYNOPSIS
        Get one or more groups from RedSeal
    .PARAMETER GroupPath
        Full path to the group
    .PARAMETER XML
        Boolean switch to return the raw XML instead of a parsed object
    .OUTPUTS
        One custom object per group.
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [String]
        $GroupPath = "/Server+Core+Zoning+Standards/Clients",
   
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )
    
    begin {
    }

    process {

        $uri = "https://" + $script:Server + "/data/group" + $grouppath
        
        Write-Debug "Query URI is $uri"

        $groupXml = Invoke-RestMethod -Uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"

        Write-Debug "Response is $($groupXml.InnerXML.tostring())"

        if ($recurse -and ($groupXml.group.groups.group.path).count -ge 1) {
            $groupXml.group.groups.group.path | Get-RSGroup
        }

        if ($XML) {
            $groupXml
        } else {
            [pscustomobject] @{GroupName = $groupXml.group.Name
                GroupPath    = $groupXml.group.path
                GroupComment = $groupXml.group.comments
                SubGroupName = $groupXml.group.groups.group.name
                SubGroupPath = $groupXml.group.groups.group.path
                SubnetID     = $groupXml.group.subnets.subnet.id
                HostTreeID   = $groupXml.group.computers.host.TreeID
                HostName     = $groupXml.group.computers.host.Name
                DeviceName   = $groupXml.group.computers.device.Name
                DeviceTreeID = $groupXml.group.computers.device.TreeID
            }
        }
    }

}

function Get-RSSubnet {
    <#
    .SYNOPSIS
        Get info on a given subnet
    .PARAMETER TreeID
        TreeID of subnet object
    .PARAMETER Name
        Name of the subnet to get
    .OUTPUTS
        One custom object per subnet.
#>

    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID= $null,
        
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name = $null

    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/subnet/$Name" 
        } else {
            $uri = "https://$script:server/data/subnet/id/$TreeID"
        }

        $subnetXml = Invoke-RestMethod -uri $uri  -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"

        #$subnetXml
        [pscustomobject] @{TreeID = $subnetXml.subnet.id
            Name = $subnetXml.subnet.name
            Description = $subnetXml.subnet.description
            HostTreeID = $subnetXml.subnet.hosts.host.treeid
            HostName = $subnetXml.subnet.hosts.host.name
        }
    }

}

function Get-RSDevice {
    <#
    .SYNOPSIS
        Get info on a given host
    .PARAMETER TreeID
        RedSeal TreeID for a host object
    .PARAMETER ServerName
        DNS name of the RedSeal server
    .PARAMETER Credential
        Credential object for the RedSeal server
    .OUTPUTS
        One custom object per host.
#>
    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID = $null,

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name = $null
            
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
        $deviceXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"

        Write-Debug "XML returned is at deviceXml.innerXML"

        if ($deviceXml.message.text -like 'No host*') {
            [pscustomobject] @{Message = "No Device found"}
        } elseif ($deviceXml.list) {
            $deviceXml.list.device | % { Get-RSDeviceDetail $_ }
        } else {
            Get-RSDeviceDetail $deviceXml.device   
        }
      
        
    }
}

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

        Write-Verbose "Fetching configurtaion object."
        $uri = $deviceDetailXml.Configuration.URL
        $configXML = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
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

function Get-RSHost {
    <#
    .SYNOPSIS
        Get info on a given host
    .PARAMETER TreeID
        RedSeal TreeID for a host object
    .PARAMETER ServerName
        DNS name of the RedSeal server
    .PARAMETER Credential
        Credential object for the RedSeal server
    .OUTPUTS
        One custom object per host.
#>
    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID = $null,

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name = $null
            
    )

    begin {
        
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/host/$Name"
        } else {
            $uri = "https://$script:server/data/host/id/$TreeID"
        }
        
        Write-Verbose "Fetching host object."   
        $hostXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"

        Write-Debug "XML returned is at hostXml.innerXML"

        if ($hostXml.message.text -like 'No host*') {
            [pscustomobject] @{Message = "No host found"}
        } elseif ($hostXml.list) {
            $hostXml.list.host | % { Get-RSHostDetail $_ }
        } else {
            Get-RSHostDetail $hostXml.host    
        }
        
        
    }
}

function Get-RSHostDetail {
    <#
    .SYNOPSIS
        Prases host XML to return host and metrics data
    .PARAMETER HostXML
        RedSeal Host XML GET response
    .OUTPUTS
        One custom object
#>
    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        $HostDetailXml
    )

    begin {
    }

    process {

        Write-Verbose "Fetching metrics object."
        $uri = $hostDetailXml.Metrics.URL
        $metricsXML = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        Write-Debug "Metrics XML is at metricsXml.innerxml"
        
        [pscustomobject] @{TreeID = $hostDetailXml.TreeID
                Hostname = $hostDetailXml.Name
                SpecifiedValue = [int]$hostDetailXml.Value
                LastModifiedDate = ConvertFrom-RSDate $hostDetailXml.LastModifiedDate
                LastScannedDate = ConvertFrom-RSDate $hostDetailXml.LastScannedDate
                OperatingSystem = $hostDetailXml.OperatingSystem
                AttackDepth = [int]$metricsXML.Metrics.AttackDepth
                Exposure = $metricsXML.Metrics.Exposure
                Value = [int]$metricsXML.Metrics.Value
                Risk = [int]$metricsXML.Metrics.Risk
                DownstreamRisk = [int]$metricsXML.Metrics.DownstreamRisk
                Leapfroggable = [System.Convert]::ToBoolean($metricsXML.Metrics.Leapfroggable)
                Exploitable = [System.Convert]::ToBoolean($metricsXML.Metrics.Exploitable)
                IPAddress = $hostDetailXml.Interfaces.Interface.Address
        }
    }
}

function Set-RSHost {
    <#
    .SYNOPSIS
        Create or update a host object
    .PARAMETER HostObject
        Host object to update. May be an array of hosts.
    .PARAMETER TreeID
        TreeID of the host object to modify.
    .INPUTS
        Full host object.
    .OUTPUTS
        One result object.
#>

    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [String[]]
        $HostObject

    )

    begin {
        if ($Credentials -eq $null) {
            $Credentials = Get-Credential -Message "Enter RedSeal credentials"
        }
    }

    process {

        foreach ($host in $HostObject) {
            $hostname
            $interfaces
            $interface.address
            $applications
            $application.IP
            $application.portandprotocol
            $application.portandprotocol.port
            $application.portandprotocol.protocol
            $application.vulnerabilities

            #post XML to RedSeal server

        }
    }
}



function Set-RSHostValue {
    <#
    .SYNOPSIS
        Sets a custom business value on a given host
    .PARAMETER SpecifiedValue
        Value to set for host objext.
    .PARAMETER TreeID
        TreeID of the host object to modify
    .INPUTS
        TreeID of the host object to modify
    .OUTPUTS
        One result object.
#>

    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [String]
        $TreeID = $null,
    
        [Parameter(Mandatory=$false, Position=1)]
        [Int]
        $SpecifiedValue=1

    )

    begin {
        if ($Credentials -eq $null) {
            $Credentials = Get-Credential -Message "Enter RedSeal credentials"
        }
    }

    process {
            
        $hostXml = Invoke-RestMethod -uri "https://$script:server/data/host/id/$TreeID" -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"

        #If no value set, set it now, otherwise change it to the new value
        if($hostXml.host."Value" -eq $null) { 
            $e = $hostXml.CreateElement("Value")
            $e.InnerText = "$SpecifiedValue"
            $hostXml.host.AppendChild($e) | Out-Null
        } else {
            $hostXml.host."Value" = "$SpecifiedValue"
        }

        #create a processing directive for the mandatory header
        $pi = $hostXml.CreateProcessingInstruction("RedSeal", 'mediaType="application/x-RedSealv6.0+xml"')
        $hostXml.InsertBefore($pi, $hostXml.ChildNodes[2]) | Out-Null

        #create a new GUID to serve as a multipart form boundary
        $boundary = [System.Guid]::NewGuid().ToString()

        #set the body of the HTTP post
        $respBody = @"
--$boundary
Content-Disposition: form-data; name="File"; filename="test.xml"
Content-Type: application/xml

$($hostXml.InnerXML.ToString().Replace("><",">`r`n<"))

--$boundary--
"@

        #post the updated XML
        $result = Invoke-RestMethod -uri "https://$script:server/data/host/id/$TreeID" -Credential $script:credentials -method Post -ContentType "application/xml; boundary=$boundary" -Body $respBody

        #check for results here (TBD)
        [pscustomobject] @{Status = $result.ImportResult.Status
            Hostname = $hostXml.host.Name
            SpecifiedValue = $specifiedValue 
            TreeID = $TreeID}
    }
}

function Get-RSReportList {
    <#
.SYNOPSIS
    Gets available RedSeal reports
.DESCRIPTION
    Gets all available RedSeal reports
.OUTPUTS
    One report object per visible report.
#>
    [cmdletbinding()]
    Param(
    
    )

    begin {
    }

    process {
 
        $reportListXml = Invoke-RestMethod -Uri "https://$script:server/data/reports" -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"

        $reportListXml.List.Report | % {
            [pscustomobject] @{Name = $_.Name
                Description = $_.Description
                DesignFile = $_.DesignFIle
                Owner = $_.Owner
                LastEditor = $_.LastEditor
                ModifiedDate = ConvertFrom-RSDate $_.ModifiedDate
                ReportURL = $_.URL
             }
         }

    }

}

function Read-RSReport {
    <#
.SYNOPSIS
    Reads RedSeal report
.DESCRIPTION
    Reads RedSeal reports and converts the RedSeal XML into usable objects.
.Example
    Read-RSReport Remediation+Priorities+%28Web+Report%29
    Read-RSReport -ReportName https://servername/data/report/All+Exposed+Vulnerabilities+with+Patches
#>


    [CmdletBinding(DefaultParameterSetName='ReportUrl')]
    param(
        # The URL for the reports
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = 'ReportURL')]
        [string]$ReportName,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ReportFile', ValueFromPipelineByPropertyName = $true)]
        [Alias('Fullname')]
        [string]
        $File
    
    )

    begin {

    # Nesting this function
    function Get-HTTP {
        param(
            [Parameter(Mandatory=$true)]
            [string]$username,

            [Parameter(Mandatory=$true)][string]$password,
        
            #full URL to the RS report to fetch
            [Parameter(Mandatory=$true)][string]$url,

            [Timespan]$Timeout = "2:10:0",
        
            [string]$UserAgent = "PowerShell RedSeal POC",
        
            [string]$Accept = "*/*"
        )

        $req = [Net.HTTPWebRequest]::Create($url)
        $bytes = [Text.Encoding]::UTF8.GetBytes($username+":" + $password)
        $authinfo = [Convert]::ToBase64String($bytes)
        $req.Headers.Add("Authorization", "Basic " + $authinfo)

        #Set timeout (ms) value for the web request, defined by how long RedSeal takes to create the report
        $req.Timeout = $Timeout.TotalMilliSeconds

        $req.UserAgent = $UserAgent
        $req.Accept = $Accept

        #$req.ContentType = "text/html"
        $req.Method ="GET"
        $req.ContentLength = 0

        Write-Progress -Activity "Getting report" -Status "Sending request and awaiting response"
        try {
            $resp = $req.GetResponse()
        } catch {
            $ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
            $Matched = ($ErrorMessage -match '[0-9]{3}')
            if ($Matched) {
                Write-Error -Message ('HTTP status code was {0} ({1})' -f $HttpStatusCode, $matched);
            } else {
                Write-Error -Message $ErrorMessage;
            }

            Write-Error -Message $Error[0].Exception.InnerException.Response
            return
        }

        Write-Verbose "Reading response"
        $reader = new-object System.IO.StreamReader($resp.GetResponseStream())
        Write-Output $reader.ReadToEnd()

        #clean up
        $reader.close()
      
        $resp.close()

    }

        # This code reads specific XML elements from a stream using XmlTextReader
        # (for speed and memory consumption)
        $fastReadXml = Add-Type -PassThru -ReferencedAssemblies System.Xml @"
using System;
using System.IO;
using System.Xml;
using System.Collections;
using System.Collections.Generic;

namespace FastImport {

    public class FastImportXml$(Get-Random)
    {
        public static IEnumerable<string> LoadXml(Stream stream, string[] element)
        {
            Hashtable matchingElements = new Hashtable();
            foreach (string elementName in element) {
                matchingElements.Add(elementName, elementName);
            }
            string matchStart = String.Empty;
            XmlTextReader reader =  new XmlTextReader(stream);
            StreamReader streamReader = new StreamReader(stream);
            XmlNodeType lastType;
            bool inElement = false;
            long streamOffset = 0;

            while (reader.Read()) {
                if (reader.NodeType == XmlNodeType.Element) {

                    if (! inElement) {
                        string elementName = reader.Name;
                        if (matchingElements.ContainsKey(elementName))  {

                            yield return "<" + reader.Name + ">" + reader.ReadInnerXml() + "</" + elementName + ">" ;
                            streamOffset = stream.Position;
                            matchStart = reader.Name;
                            continue;
                        }
                    }
                    if (inElement) {

                        // yield return reader.Name;
                    }

                } else if (reader.NodeType == XmlNodeType.EndElement) {
                    if (matchingElements.ContainsKey(reader.Name))  {
                        if (reader.Name == matchStart) {
                            inElement = false;

                            yield return (reader.Name + "-" + streamOffset.ToString() + "-" + stream.Position.ToString());
                        }
                    }
                }

                lastType = reader.NodeType;

            }
        }
    }
}
"@ |
    Select-Object -First 1
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ReportUrl') {
            $un = $script:credentials.GetNetworkCredential().Username
            $pass = $script:credentials.GetNetworkCredential().Password
            [uri]$ReportUrl = "https://$script:server/data/report/$reportName"
            Write-Progress "Getting Report" "  "
            $httpResponse = Get-HTTP -Username $un -Password $pass -Url $ReportUrl
            Write-Progress "Creating Memory Stream" "  "        
            $s = [IO.MemoryStream]([Text.Encoding]::UTF8.GetBytes($httpResponse))
        } elseif ($PSCmdlet.ParameterSetName -eq 'ReportFile') {
            $resolvedFile = $ExecutionContext.SessionState.Path.GetResolvedPSPathFromPSPath($file)
            if (-not $resolvedFile) { return }
            $s = [IO.File]::OpenRead("$resolvedFile")
        }

        Write-Progress "Searching for MetaData stanzas" "  "
        #extract each MetaData stanza
        #Performance issue: we read all the way to the end of the file, looking for metadata stanzas
        $metaData = @($fastReadXml::LoadXml($s, "MetaData"))
        
        $null = $s.Seek(0, "Begin")
        $names = $metaData | foreach { ($_ -as [xml]).MetaData.Name }

        $rowInt = 0
        $perc = 0
        Write-Progress "Unwinding XML" "  "
        foreach ($object in $fastReadXml::LoadXml($s, "object-array")) {
            $xmlObject = [xml]$object
            $perc += 5
            if ($perc -gt 100) { $perc = 0 }
            Write-Progress -activity "Unwinding XML" -status "Processing row $rowint" -percentcomplete $perc
            
            #We use the SelectChildren method to ensure that empty columns are also returned
            $values = $xmlObject."object-array".CreateNavigator().SelectChildren('Element').Value
            #$values = $xmlObject |
            #    Select-Xml "//descendant::text()" |
            #    ForEach-Object { $_.Node.Value }
            
            $table = @{}
            $nc = 0
            foreach ($n in $names) {
                $table[$n] = $values[$nc]
                $nc++
            }
            New-Object PSObject -Property $table

            $rowInt++
        }
        $s.Close()
        $s.Dispose()

    }
}