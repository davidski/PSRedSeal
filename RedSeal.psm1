#Author: David F. Severski
#Date: 7/28/2013
#Purpose: Expose the RedSeal API via PowerShell
#doesn't yet support impact or detailed path queries
#group modifications pending bug fixes in RedSeal API

#default server name
$script:Server = "ppxsec04.childrens.sea.kids"

function Send-RSRequest {
    <#
    .SYNOPSIS
        Hack to allow selecting the desired version of the RedSeal API given the broken state of the Invoke-RestMethod cmdlet
    .PARAMETER uri
        URI to query
    .PARAMETER method
        HTTP method to use, defaults to GET
    .PARAMETER timeoutsec
        Number of seconds for timeout, defaults to 600 (10 minutes)
    .OUTPUTS
        Returns XML from the RedSeal server as an XML object
#>
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Uri,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("GET", "DELETE", "HEAD", "PUT", "POST")]
        [string]
        $Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]
        $Body,

        [Parameter(Mandatory = $false)]
        [int]
        $TimeoutSec = (10*60)

    )

    # generate basic auth string
    $basicPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:Credentials.Password))
    $basicUsername = $script:Credentials.UserName
    $token = $basicUsername + ":" + $basicPassword
    $token = [Convert]::ToBase64String([Text.Encoding]::Ascii.GetBytes($token))

    #$webRequest.Credentials = $script:Credentials

    $webRequest = [System.Net.WebRequest]::Create( $uri )
    $webRequest.PreAuthenticate = $true
    $webRequest.Method = $method
    $webRequest.Headers.Add('Authorization', "Basic $token")
    $webRequest.Accept = 'application/x-RedSealv' + $script:APIVersion + '+xml'
    $webRequest.KeepAlive = $false
    $webRequest.UserAgent = "PowerShell-RedSeal"
    $webRequest.Timeout = ($TimeoutSec * 1000)


    #Write-Warning "Request is $webrequest"
    #Start-Sleep -Milliseconds 100

    if ($Method -eq 'PUT') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body) 
        #$webRequest.ContentType = $encoding
        $webRequest.ContentLength = $bytes.Length
        
        [System.IO.Stream] $outputStream = [System.IO.Stream]$Webrequest.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)  
        $outputStream.Close()
    } elseif ($method -eq 'POST') {

        #create a new GUID to serve as a multipart form boundary
        $boundary = [System.Guid]::NewGuid().ToString()

        #set the body of the HTTP post
        $respBody = @"
--$boundary
Content-Disposition: form-data; name="File"; filename="RSPoSH.xml"

$body

--$boundary--
"@

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($respbody) 
        $webRequest.ContentType = "multipart/form-data; boundary=" + $boundary
        $webRequest.ContentLength = $bytes.Length
        
        [System.IO.Stream] $outputStream = [System.IO.Stream]$Webrequest.GetRequestStream()
        $outputStream.Write($bytes, 0, $bytes.Length)  
        $outputStream.Close()
    }
    
    $errorMessage = $null
    try {
        $response = $webRequest.GetResponse()
    }
    catch [Net.WebException] {
        #$errorMessage = $Error[0].Exception.ToString()
        $ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message
        $Matched = ($ErrorMessage -match '[0-9]{3}')
        if ($Matched) {
            Write-Error -Message ('HTTP status code was {0} ({1})' -f $HttpStatusCode, $matched)
        } else {
            Write-Error -Message $ErrorMessage
        }

        Write-Error -Message $Error[0].Exception.InnerException.Response
        return
    }
    if (!$errorMessage) {
        $stream = $response.GetResponseStream()
        #$reader = new-object System.IO.StreamReader($response.GetResponseStream())
        $reader = [io.streamreader]($stream)
        [xml]$reader.ReadToEnd()
        $stream.flush()
        $stream.close()
    } else {
        Write-Warning "Error communicating with RedSeal: $errorMessage"
    }
}

function Set-RSDataQuery {
    <#
    .SYNOPSIS
        Sets a RS Data Query object (RS 6.6+ API)
    .PARAMETER Group
        Group path to filter/group results
    .PARAMETER QueryType
        Type of DataQuery to run
    .PARAMETER QueryTarget
        Host or subnet information
    .PARAMETER QueryFilter
        ID, Name, or IP of the QueryTarget
    .PARAMETER XML
        Return raw XML
    .PARAMETER TimeoutSec
        HTTP timeout value
    .OUTPUTS
        A DataQuery XML blob
    #>
}

function Invoke-RSDataQuery {
    [cmdletbinding()]
    Param(

        [Parameter(Mandatory = $false)]
        [String]
        $Group = "/Topology",
        
        #currently, Metrics is the only valid API type
        [Parameter(Mandatory = $false)]
        [ValidateSet('Metrics')]
        [String]
        $QueryResult = "Metrics",

        [Parameter(Mandatory = $false)]
        [ValidateSet('Host', 'Subnet', IgnoreCase = $false)]
        [String]
        $QueryTarget = "Host",

        [Parameter(Mandatory = $false)]
        [String]
        $QueryFilter,
        
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML,

        [Parameter(Mandatory = $false)]
        [Int]
        $TimeoutSec = 60*2

    )

    begin {
    }

    process {

        $queryXml = New-Object XML
        $e = $queryXml.CreateElement("DataQuery")
        $queryXml.AppendChild($e) | Out-Null
        $e = $queryXml.CreateElement("Search")
        $queryXml.SelectSingleNode("/DataQuery").AppendChild($e) | Out-Null
        $e = $queryxml.CreateElement("Target")
        $queryXml.SelectSingleNode("/DataQuery/Search").AppendChild($e) | Out-Null

        $queryXml.DataQuery.Search.Target = $QueryTarget
        
        if ($QueryFilter) {
            $e = $queryxml.CreateElement("Text")
            $queryXml.SelectSingleNode("/DataQuery/Search").AppendChild($e) | Out-Null
            $queryXml.DataQuery.Search.Text = $QueryFilter
        } 
        
        $e = $queryxml.CreateElement("Result")
        $e.InnerText = $queryResult
        $queryXml.SelectSingleNode("/DataQuery").AppendChild($e) | Out-Null
       
        #fetch the details of the requested group
        $groupDetails = Get-RSGroup $Group
        
        $e = $queryxml.CreateElement("Group")
        $queryXml.SelectSingleNode("/DataQuery").AppendChild($e) | Out-Null

        $e = $queryXml.CreateElement("Name")
        $e.InnerText = $groupDetails.GroupName
        #$e.InnerText = "Topology"
        $queryXml.SelectSingleNode("/DataQuery/Group").AppendChild($e) | Out-Null

        #set source clause specific options
        $e = $queryXml.CreateElement("Path")
        #$e.InnerText = "/Topology"
        $e.InnerText = $groupDetails.GroupPath
        $queryXml.SelectSingleNode("/DataQuery/Group").AppendChild($e) | Out-Null
        

        #set the body of the HTTP put
        $respBody = $($queryXml.InnerXML.ToString().Replace("><",">`r`n<"))
        
        Write-Verbose "Query put body is: $respBody"
        
        $uri = "https://$script:server/data"
        Write-Verbose "URI is $uri"

        #finally, try to execute the query
        try {

            #$resultXml = Invoke-RestMethod -uri $uri -body $respBody -Credential $script:Credentials -Method Put -ContentType 'application/xml' -TimeoutSec $timeoutSec -DisableKeepAlive
            $resultXML = Send-RSRequest -uri $uri -Method Put -body $respBody

        }
        catch {
            Write-Warning "Put body was `r`n$respBody"
            throw $_.Exception.Message
        }

        Write-Verbose "DataQuery exectution time: $($resultXML.DataQueryResults.Duration)"

        if ($XML) {
            $resultXml
        } else {
            #parse the results
            Get-RSMetricsGroup $resultXml.DataQueryResults.Results.Group
        }
    }
}

function Get-RSAdminTaskHistory {
<#
    Retrieves task history
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [switch]$XML = $false
    )

    begin {
    }

    process {

        $uri = $uri = 'https://' + $script:Server + '/data/system/adminoperation'
        $response = Send-RSRequest -Uri $uri -Method GET

        if ($XML) {
            $response
        } else {
            #parse the response
            if ($response.message) {
                $response.message
            } else {
                #emit parsed object
                foreach ($taskObj in $response.list.AsyncTaskTrackerData) {
                    [pscustomobject]@{
                        URL          = $taskObj.URL
                        ID           = $taskObj.ID
                        Description  = $taskObj.Description
                        Finished     = [boolean]$taskObj.IsTaskFinished
                        CompletionPercentage = $taskObj.CompletionPercentage
                        JobStateInfo = $taskObj.Status
                        TextStatus   = $taskObj.TextStatus
                        TimeQueued   = ConvertFrom-RSDate $taskObj.QueueTime
                        BeginTime    = ConvertFrom-RSDate $taskObj.StartTime
                        EndTime      = ConvertFrom-RSDate $taskObj.EndTime
                        Error        = $taskObj.Exception
                        Result       = $taskObj.Result
                    }
                }
            }
        }   
    }
}

function Start-RSAdminTask {
<#
    Initiates an administrative task
#>
    [cmdletbinding()]
    Param(
        
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $True)]
        [ValidateSet("Backup", "Restore", "PluginUpload", "ImageSetNext", "ImageDelete", "RebootAppliance")]        
        $TaskType

    )

    begin {
    }

    process {

        $taskXml = New-Object XML

        $decl = $taskXml.CreateXmlDeclaration("1.0", $null, $null)
        $decl.Encoding = "ISO-8859-1"
        $taskXml.InsertBefore($decl, $taskXml.DocumentElement) | Out-Null
        
        $e = $taskXml.CreateElement("AdminOperationCommand")
        $taskXml.AppendChild($e) | Out-Null
        
        $e = $taskXml.CreateElement("Action")
        $e.innertext = $TaskType
        $taskXml.SelectSingleNode("/AdminOperationCommand").AppendChild($e) | Out-Null
        
        #ImageSetNext sepcific (hardcoded ATM)
        $e = $taskXml.CreateElement("ImageName")
        $e.innertext = "RedSeal 6.6.1 (Build-374)"
        $taskXml.SelectSingleNode("/AdminOperationCommand").AppendChild($e) | Out-Null
   
        $reqBody = $taskXml.innerxml.ToString().Replace("><", ">`r`n<")

        $uri = 'https://' + $script:Server + '/data/system/adminoperation'
    
        Write-Verbose "Request is: $reqBody"

        $response = Send-RSRequest -Method PUT -Body $reqBody -Uri $uri

        $response
    
    }
}

function Get-RSMetricsGroup {
<#
    Parses a single metrics query group
#>
    [cmdletbinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $True)]
        $DataQueryResults

    )

    begin {
    }

    process {

        Write-Verbose "Working on $($DataQueryResults.Path.ToString())"
        
        foreach ($metricObject in $DataQueryResults.Results.Metrics) {
            Get-RSMetricsDetail -QueryLeaf $metricObject -GroupPath $DataQueryResults.Path.ToString()
        }
        if ($DataQueryResults.Groups) {
            foreach ($group in $DataQueryResults.groups.group) {
                Get-RSMetricsGroup $group
            }
        }
    }
}

function Get-RSMetricsDetail {
<#
    .SYNOPSIS
        Internal function for parsing DataQuery results objects into host objects
    .INPUT
        Expects one metrics object and the path to that object
    .OUTPUTS
        Returns one host metrics object for each metrics result
#>
    [cmdletbinding()]
    Param(
        [Parameter(mandatory = $true)]
        $QueryLeaf,

        [Parameter()]
        $GroupPath

    )

    begin {
    }

    process {
        [pscustomobject]@{
            Name           = $QueryLeaf.Name
            GroupPath      = $GroupPath
            TreeID         = $QueryLeaf.TreeID
            AnalysisDate   = ConvertFrom-RSDate $QueryLeaf.AnalysisDate
            PrimaryService = $QueryLeaf.PrimaryService
            Vendor         = $QueryLeaf.Vendor
            OS             = $QueryLeaf.OS
            AttackDepth    = $QueryLeaf.AttackDepth
            Exposure       = $QueryLeaf.Exposure
            Value          = $QueryLeaf.Value
            ServicesCount  = $QueryLeaf.ServicesCount
            VulnerabilityCount = $QueryLeaf.VulnerabilityCount
            Risk           = $QueryLeaf.Risk
            DownstreamRisk = $QueryLeaf.DownstreamRisk
            Confidence     = $QueryLeaf.Confidence
            Leapfroggable  = [boolean]$QueryLeaf.Leapfroggable
            Exploitable    = [boolean]$QueryLeaf.Exploitable
            PrimaryIP      = $QueryLeaf.PrimaryIP
            AccessibleFromUntrusted = [boolean]$QueryLeaf.AccessibleFromUntrusted
            HasAccesstoCritical = [boolean]$QueryLeaf.HasAccessToCritical
        }
    }
}

function Start-RSAnalysis {
    <#
    .SYNOPSIS
        Begins an analysis response
    .PARAMETER xml
        Retrieve XML rather than a parsed status response
    .OUTPUTS
        None
#>
    [cmdletbinding()]
    Param(
        [Parameter(mandatory = $false)]
        [switch]
        $XML = $false

    )

    begin {
    }
    process {
        $analysisXml = New-Object XML
        $e = $analysisXml.CreateElement("AnalysisCommand")
        $analysisXml.AppendChild($e) | Out-Null
        $e = $analysisXml.CreateElement("Analysis")
        $e.innertext = "OVERALL"
        $analysisXml.SelectSingleNode("/AnalysisCommand").AppendChild($e) | Out-Null
        $e = $analysisXml.CreateElement("Action")
        $e.innertext = "Run"
        $analysisXml.SelectSingleNode("/AnalysisCommand").AppendChild($e) | Out-Null

        $reqBody = $analysisXml.innerxml.ToString().Replace("><", ">`r`n<")

        $uri = 'https://' + $script:Server + '/data/metrics'
        #Write-Warning $reqBody
        $response = Send-RSRequest -uri $uri -Method PUT -Body $reqBody

        if ($response.Message) {
            $response.Message
        } else {
            if ($XML) {
                $response.AnalysisStatus
            } else {
                [pscustomobject]@{
                    Status = $response.AnalysisStatus.RunningAnalysis.Status
                }
            }
        }

    }
}
function Connect-RSServer {
    <#
    .SYNOPSIS
        Set connection parameters for the RedSeal cmdlets
    .OUTPUTS
        None
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

    $uri = "https://" + $script:Server + "/data/system"
    if (![xml](Send-RSRequest -uri $uri -Method HEAD)) {
        $script:Credentials = $null
        Throw "Unable to connect to RedSeal!"
    }

    if ((Get-RSSystemStatus).RedSealVersion -like '*6.0*') {
        $script:APIVersion = "6.0"
        Write-Warning "Compatibility with RedSeal pre-6.6 API deprecated and no longer tested!"
    } else {
        $script:APIVersion = "6.6"
    }

}

function Get-RSConnection {
    [pscustomobject]@{
        Server      = $script:Server
        Credentials = $script:Credentials
        APIVersion  = $Script:APIVersion
    }
}

function Get-RSSystemStatus {
    <#
    .SYNOPSIS
        Fetch the system status of the RedSeal Server
    .OUTPUTS
        A single system status object
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )

    begin {

        $uri = "https://" + $script:Server + "/data/system"

        #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials
        $resultXml = Send-RSRequest -uri $uri

        if ($XML) {
            $resultXml
        } else {

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
                RedSealVersion = $(if ($resultXml.SystemStatus.RedSealVersion -ne $null) {
                    $resultXml.SystemStatus.RedSealVersion } else {
                    "RedSeal 6.0 (Build unknown)" })
                HardDiskSummary = $(if ($resultXml.SystemStatus.RedSealVersion -eq $null) {
                    $null } else {
                    [pscustomobject]@{
                        DiskUtilization = [int]$resultXML.SystemStatus.HardDiskSummary.DiskUtilization
                        RaidDiskStatus = $resultXML.SystemStatus.HardDiskSummary.RaidDiskStatus
                        TotalSpace = [int]$resultXML.SystemStatus.HardDiskSummary.TotalSpace
                        FreeSpace = [int]$resultXML.SystemStatus.HardDiskSummary.FreeSpace                        
                        EstimatedBackupSizeWithAnalysis = [int]$resultXML.SystemStatus.HardDiskSummary.EstimatedBackupSizeWithAnalysis
                        EstimatedBackupSizeWithoutAnalysis = [int]$resultXML.SystemStatus.HardDiskSummary.EstimatedBackupSizeWithoutAnalysis
                     }
                 })
            }
        }
    }
}

function Get-RSSystemLicense {
    <#
    .SYNOPSIS
        Fetch the system license of the RedSeal Server
    .OUTPUTS
        A single system license object
    .PARAMETER xml
        Switch to return the raw XML response rather than a parsed object

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )

    begin {

        $uri = "https://" + $script:Server + "/data/system/license"

        #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials
        $resultXml = Send-RSRequest -uri $uri

        if ($XML) {
            $resultXml
        } else {

            [pscustomobject]@{
                State = $resultXml.LicenseInfoData.State
                LicenseExpirationDate = $resultXml.LicenseInfoData.LicenseExpiryDate
                MainteanceExpirationDate= $resultXml.LicenseInfoData.MaintenanceExpiryDate
                LicenseCount = $resultXml.LicenseInfoData.NumberofDeviceLicensed
                LicensesInUse = $resultXml.LicenseInfoData.CurrentDevicesInModel
                LicenseExceeded = [System.Convert]::ToBoolean($resultXml.LicenseInfoData.IsLicensedDeviceExceeded)
                Warnings = $resultXml.LicenseInfoData.Warnings
            }
        }
    }
}


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
    [cmdletbinding(DefaultParametersetName="empty")]
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

        $rawXml.AccessResults.TrafficSegment | ForEach-Object {
                
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
    .PARAMETER RawXML
        Raw XML to parse
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

         $rawXml.ThreatResults.ThreatSegment | foreach {
                
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
    .PARAMETER RawXML
        Raw impact XML to parse
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


        $rawXml.SecurityImpact | foreach {
        
            $table = @{}
            $table.add("Status", "Impact")
            $table.add("PathStatus", $_.PathStatus)
            $table.add("SourceExposureType", $_.SourceExposureType)
            $table.add("DestinationExposureType", $_.DestinationExposureType)
            $table.add("ExposedVulnerabilities", $_.ExposedVulnerabilities)
            $table.add("UniqueVulnerabilities", $_.Destination.UniqueVulnerabilities)
            $table.add("OldestScan", $(ConvertFrom-RSDate $_.Destination.OldestScan))
            $table.add("MaxCVSS", $_.Destination.MaxCVSS)
            $table.add("LeapFrog", $_.Destination.LeapFrog)
            $table.add("NumberOfHosts", $_.Destination.NUmberOfHosts)
            if ($table.LeapFrog -eq $true) {
                $table.add("ReachableHosts", $_.Downstream.Destinations.LeapFrog)
            }

            [pscustomobject] $table
        }
    }
}

function Read-RSPathResult {
    <#
    .SYNOPSIS
        Parses XML from a RedSeal detailed path query
    .PARAMETER RawXML
        Raw path XML to parse
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

        $rawXml.PathResult.Paths.Path | foreach {
                
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
    .PARAMETER RSDate
        RedSeal SQL date string
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

function ConvertTo-RSDate {
    <#
    .SYNOPSIS
        Converts from .NET datetime object to RedSeal timezone date
    .PARAMETER RSDate
        .NET datetime object
    .OUTPUTS
        A RedSeal datetime string
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [DateTime]
        $RSDate
    )

    process {

        Write-Verbose "Received a raw date of $RSDate"

        if ($RSDate -ne $null) {
            $RSDate =  $RSDate | Get-Date -Format "MMM dd, yyyy hh:mm:ss tt PST"
        } else {
            $RSDate =  Get-Date -Format "MMM dd, yyyy hh:mm:ss tt PST"
        }

        $RSDate

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

        #$viewXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $viewXml = Send-RSRequest -uri $uri
        
        $viewXml.list.view | foreach {

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
    .PARAMETER Recurse
        Crawl through subgroups and return individual group objects
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
        $XML = $false
    )
    
    begin {
    }

    process {

        $uri = "https://" + $script:Server + "/data/group" + $groupPath
        
        Write-Debug "Query URI is $uri"

        #$groupXml = Invoke-RestMethod -Uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $groupXml = Send-RSRequest -uri $uri

        Write-Debug "Response is $($groupXml.InnerXML.tostring())"

        if ($groupXml.message.text -like 'No group found*') {
            return $groupXML.message.text
        }

        $groupXml = $groupXml.FullGroup

        #if we have subgroups, test if recursion is requested and whether recursion
        #should return parsed objects or the raw XML
        if ($recurse -and ($groupXml.groups.group.path).count -ge 1) {
            $groupXml.groups.group.path | Get-RSGroup -Recurse -XML:$XML
        } else {    

            if ($XML) {
                $groupXml
            } else {
                [pscustomobject] @{
                    GroupName    = $groupXml.Name
                    GroupPath    = $groupXml.path
                    Comments     = $groupXml.comments
                    SubGroupName = $groupXml.SelectNodes("/FullGroup/Groups/Group/Name")."#text"
                    SubGroupPath = $groupXml.SelectNodes("/FullGroup/Groups/Group/Path")."#text"
                    SubGroups      = $groupXml.SelectNodes("/FullGroup/Groups/Group") |
                         ForEach-Object  { 
                            [pscustomobject]@{
                                Name = $_.Name
                                URL = $_.URL
                                Path = $_.Path
                            }
                        } 
                    SubnetID     = $groupXml.SelectNodes("/FullGroup/Subnets/Subnet/ID")."#text"
                    Subnets      = @($groupXml.SelectNodes("/FullGroup/Subnets/Subnet") |
                         ForEach-Object  { 
                            [pscustomobject]@{
                                Name = $_.Name
                                URL = $_.URL
                                CIDR = $_.CIDR
                                ID = $_.ID
                                TrustLevel = $_.TrustLevel
                                Description = $_.Description
                            }
                        })
                    HostTreeID   = $groupXml.SelectNodes("/FullGroup/Computers/Host/TreeId")."#text"
                    HostName     = $groupXml.SelectNodes("/FullGroup/Computers/Host/Name")."#text"
                    Hosts        = @($groupXml.SelectNodes("/FullGroup/Computers/Host") | 
                        ForEach-Object  { 
                            [pscustomobject]@{
                                Name = $_.Name
                                URL = $_.URL
                                TreeID = $_.TreeID
                            }
                        })
                    Devices      = @($groupXml.SelectNodes("/FullGroup/Computers/Device") |
                        ForEach-Object  { 
                            [pscustomobject]@{
                                Name = $_.Name
                                URL = $_.URL
                                TreeID = $_.TreeID
                                PrimaryCapability = $_.PrimaryCapability
                        }
                    })
                }
            }
        }
    }

}

function New-RSGroup {
    <#
    .SYNOPSIS
        Creates a new group custom object. To post to RedSeal, send the object to Set-RSGroup
    .OUTPUTS
        One custom object
#>
    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        $GroupName,

        [Parameter(Mandatory = $false)]
        $GroupPath,

        [Parameter(Mandatory = $false)]
        $IPAddress,

        [Parameter(Mandatory = $false)]
        $Comments
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
        }
    }
}

function Set-RSGroup {
    <#
    .SYNOPSIS
        Sets or creates a group within RedSeal
    .PARAMETER Group
        Group object to set in RedSeal
    .PARAMETER XML
        Boolean switch to return the raw XML instead of a parsed object
    .OUTPUTS
        Nothing.
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [PSObject]
        $Group,
   
        [Parameter(Mandatory = $false)]
        [Int]
        $TimeoutSec = 60 * 2,

        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )
    
    begin {
    }

    process {

        $groupXML = New-Object XML
        $e = $groupXml.CreateElement("FullGroup")
        $groupXml.AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Name")
        $e.innertext = $group.GroupName
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Path")
        $e.innertext = $group.GroupPath
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Comments")
        $e.innertext = $group.Comments
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        $e = $groupXml.CreateElement("Membership")
        $groupXml.SelectSingleNode("/FullGroup").AppendChild($e) | Out-Null

        #build list of static hosts to add
        if ($group.Hosts.Count) {
            $e = $groupXml.CreateElement("StaticComputers")
            $groupXml.SelectSingleNode("/FullGroup/Membership").AppendChild($e) | Out-Null
            foreach ($hostObj in $group.hosts) {

                $e = $groupXml.CreateElement("Host")
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Name")
                $e.innertext = $hostObj.name
                #$groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers").AppendChild($e) | Out-Null
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers/Host[last()]").AppendChild($e) | Out-Null

                <#
                $e = $groupXml.CreateElement("Host")
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("TreeID")
                $e.innertext = $hostObj.TreeID
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticComputers/Host[last()]").AppendChild($e) | Out-Null
                #>
            }
        }

        #build list of static subnets to add
        if ($group.Subnets.Count) {
            $e = $groupXml.CreateElement("StaticSubnets")
            $groupXml.SelectSingleNode("/FullGroup/Membership").AppendChild($e) | Out-Null
            foreach ($subnet in $group.Subnet) {
                $e = $groupXml.CreateElement("Subnet")
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticSubnets").AppendChild($e) | Out-Null
                $e = $groupXml.CreateElement("Name")
                $e.innertext = $subnet.id
                $groupXml.SelectSingleNode("/FullGroup/Membership/StaticSubnets/Subnet[last()]").AppendChild($e) | Out-Null
            }
        }
        
        Write-Debug $groupXML.InnerXML.ToString().Replace("><",">`r`n<")

        #set the body of the HTTP put
        $respBody = $($groupXml.InnerXML.ToString().Replace("><",">`r`n<"))

        Write-Verbose "Query put body is: $respBody"

        $uri = "https://$script:server/data/group"
        Write-Verbose "URI is $uri"

        #finally, try to execute the query
        try {
            #$resultXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -Method Put -Body $respBody -TimeoutSec $timeoutSec -DisableKeepAlive
            $resultXml = Send-RSRequest -uri $uri -Method Put -Body $respBody
        }
        catch {
            throw $_.Exception.Message
        }

        Write-Debug $resultXml.innerxml.tostring()
        #$resultXml        

    }
}

function Remove-RSGroup {
    <#
    .SYNOPSIS
        Removes a group within RedSeal
    .PARAMETER GroupPath
        Path to group to remove
    .PARAMETER XML
        Boolean switch to return the raw XML instead of a parsed object
    .OUTPUTS
        Nothing.
#>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0)]
        [String]
        $GroupPath,
   
        [Parameter(Mandatory = $false)]
        [Switch]
        $XML
    )
    
    begin {
    }

    process {

        $uri = "https://" + $script:Server + "/data/group" + $groupPath
        
        Write-Debug "Query URI is $uri"

        #$groupXml = Invoke-RestMethod -Uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $groupXml = Send-RSRequest -uri $uri -Method DELETE

        Write-Debug "Response is $($groupXml.InnerXML.tostring())"

        if ($XML) {
            $groupXml
        } else {
            $groupXml
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
        Name or IP address space of the subnet to get
    .PARAMETER XML
        Return the raw XML instead of a parsed object
    .PARAMETER Recurse
        Return objects for all alternatives, if multiple hits found
    .OUTPUTS
        One custom object per subnet.
#>

    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID = "4028aa8f2f63ce90012f63d85f6600de",
        
        [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false, ParameterSetName='SearchByName')]
        [Alias("IP")]
        [String]
        $Name,

        [Parameter(Mandatory=$false)]
        [Switch]
        $XML = $false,

        [Parameter(Mandatory=$false)]
        [Switch]
        $Recurse = $false
    )

    begin {
    }

    process {

        if ($PSCmdlet.ParameterSetName -eq 'SearchByName') {
            $uri = "https://$script:server/data/subnet/$Name" 
        } else {
            $uri = "https://$script:server/data/subnet/id/$TreeID"
        }

        #$subnetXml = Invoke-RestMethod -uri $uri -Credential $script:Credentials -ContentType "application/x-RedSealv6.0+xml"
        $subnetXml = Send-RSRequest -uri $uri



        #if alternatives are returned then fetch all the alternatives and don't return a top level object
        if ($subnetXml.selectnodes("Message/Alternatives/Subnet").count -and $Recurse) {
               $subnetXml.selectnodes("Message/Alternatives/Subnet/ID").innertext | foreach {Get-RSSubnet -TreeID $_ -XML:$xml}
        } else {

            if ($XML) {
                $subnetXml
            } else {
                [pscustomobject] @{
                    TreeID = $subnetXml.Subnet.id
                    Name = $subnetXml.Subnet.name
                    Description = $subnetXml.Subnet.Description
                    DescriptionSource = $subnetXml.Subnet.DescriptionSource
                    TrustLevel = $subnetXml.subnet.TrustLevel
                    CIDR = $subnetXML.Subnet.CIDR
                    #HostTreeID = $subnetXml.subnet.hosts.host.treeid
                    #HostName = $subnetXml.subnet.hosts.host.name
                    Hosts      = $subnetXml.SelectNodes("/Subnet/Hosts/Host") |
                        ForEach-Object  { 
                            [pscustomobject]@{
                                Name = $_.Name
                                URL = $_.URL
                                TreeID = $_.TreeID
                            }
                        }
                }        
            }
        }
    }
}

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
        $FetchAll = $False
            
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
            $hostXml.list.host | foreach { Get-RSHostDetail $_ }
        } elseif ($FetchAll) {
            $hostXml.list.host | foreach {
                [pscustomobject] @{
                    Name   = $_.name
                    URL    = $_.URL
                    TreeID = $_.TreeID
                }
            }
        } else {
            Get-RSHostDetail $hostXml.host    
        }
          
    }
}

function Get-RSHostDetail {
    <#
    .SYNOPSIS
        Parses host XML to return host and metrics data
    .PARAMETER HostDetailXML
        RedSeal Host Detail XML GET response
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
        #$metricsXML = Invoke-RestMethod -uri $uri -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $metricsXML = Send-RSRequest -uri $uri
        Write-Debug "Metrics XML is at metricsXml.innerxml"
        
        [pscustomobject] @{
                TreeID           = $hostDetailXml.TreeID
                Hostname         = $hostDetailXml.Name
                IPAddress        = $hostDetailXml.Interfaces.Interface.Address
                OperatingSystem  = $hostDetailXml.OperatingSystem
                Value            = [int]$metricsXML.Metrics.Value
                SpecifiedValue   = if ($hostDetailXml.Value) { [int]$hostdetailXML.Value } else { $null }
                AttackDepth      = [int]$metricsXML.Metrics.AttackDepth
                Exposure         = $metricsXML.Metrics.Exposure
                Risk             = [int]$metricsXML.Metrics.Risk
                DownstreamRisk   = [int]$metricsXML.Metrics.DownstreamRisk
                Leapfroggable    = [System.Convert]::ToBoolean($metricsXML.Metrics.Leapfroggable)
                Exploitable      = [System.Convert]::ToBoolean($metricsXML.Metrics.Exploitable)
                Applications     = $HostDetailXml.Applications
                LastModifiedDate = ConvertFrom-RSDate $hostDetailXml.LastModifiedDate
                LastScannedDate  = if ($hostDetailXML.LastScannedDate) { ConvertFrom-RSDate $hostDetailXml.LastScannedDate } else { $null }
                Comments         = $hostDetailXml.Comments
        }
    }
}

function New-RSHost {
    <#
    .SYNOPSIS
        Creates a new Host custom object. To post to RedSeal, send the object to Set-RSHost
    .OUTPUTS
        One custom object
#>
    [cmdletbinding()]
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

function Remove-RSHost {
    <#
    .SYNOPSIS
        Deletes a given host
    .PARAMETER TreeID
        RedSeal TreeID for a host object
    .PARAMETER Name
        DNS name of the host object
    .OUTPUTS
        Only a message
#>
    [cmdletbinding(DefaultParameterSetName='SearchByName')]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByID')]
        [String]
        $TreeID="2c9697a7316371660131f73d53b2593a",

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'SearchByName')]
        [String]
        $Name="ppwsec05.childrens.sea.kids"
            
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
        $hostXml = Invoke-RestMethod -uri $uri -Credential $script:credentials -Method DELETE
        $hostXml = Send-RSRequest -uri $uri -Method DELETE

        Write-Debug "XML returned is at hostXml.innerXML"

        if ($hostXml.message.text -like 'No host*') {
            [pscustomobject] @{Message = "No host found"}
        } elseif ($hostXml.list) {
            $hostXml.list.host | foreach { Get-RSHostDetail $_ }
        } else {
            Get-RSHostDetail $hostXml.host    
        }
    }
}


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

    [cmdletbinding()]
    Param(
    
        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
        [PSCustomObject[]]
        $HostObject,

        [Parameter(Mandatory = $false)]
        [switch]
        $XML = $false

    )

    begin {
        if ($Credentials -eq $null) {
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
 
        #$reportListXml = Invoke-RestMethod -Uri "https://$script:server/data/reports" -Credential $script:credentials -ContentType "application/x-RedSealv6.0+xml"
        $reportListXml = Send-RSRequest -Uri "https://$script:server/data/reports"

        $reportListXml.List.Report | ForEach-Object {
            [pscustomobject] @{
                Name         = $_.Name
                Description  = $_.Description
                DesignFile   = $_.DesignFIle
                Owner        = $_.Owner
                LastEditor   = $_.LastEditor
                ModifiedDate = ConvertFrom-RSDate $_.ModifiedDate
                ReportURL    = $_.URL
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
    .PARAMETER ReportName
        Name of the report to fetch and read
    .PARAMETER ReportFile
        Full path to file name to use in place of reading from RedSeal server
    .Example
        Read-RSReport Remediation+Priorities+%28Web+Report%29
        Read-RSReport -ReportName https://ppxsec04/data/report/All+Exposed+Vulnerabilities+with+Patches
        Read-RSReport -ReportFile C:\testReport.xml
#>

    [cmdletBinding(DefaultParameterSetName='ReportUrl')]
    param(
        # The URL for the reports
        [Parameter(ValueFromPipeline = $true, Mandatory = $true, Position = 0, ParameterSetName = 'ReportURL')]
        [string]$ReportName,

        [Parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1, ParameterSetName = 'ReportURL')]
        [switch]$KeepTempFile = $false,

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
        
            [string]$UserAgent = "PowerShell-RedSeal",
        
            [string]$Accept = "*/*"
        )

        $req = [Net.HTTPWebRequest]::Create($url)
        $bytes = [Text.Encoding]::UTF8.GetBytes($username + ":" + $password)
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
                Write-Error -Message ('HTTP status code was {0} ({1})' -f $HttpStatusCode, $matched)
            } else {
                Write-Error -Message $ErrorMessage
            }

            Write-Error -Message $Error[0].Exception.InnerException.Response
            return
        }

        Write-Verbose "Creating response stream"
        $reader = new-object System.IO.StreamReader($resp.GetResponseStream())

        write-Verbose "Reading response stream..."
        #Write-Output $reader.ReadToEnd()

        #dump the web response stream to a temporary file
        $tempFile = [IO.Path]::GetTempFileName()
        write-verbose "Writting response to $tempFile"
        $writer = new-object System.IO.StreamWriter($tempFile)
        $s = $reader.ReadLine()
        While ($s  -ne $null) {
            $writer.WriteLine($s)
            $s = $reader.ReadLine()
        }
        $writer.close()
        write-verbose "$tempFile complete."

        #return the name of the temporary file
        $tempFile

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
            
            Write-Progress -Activity "Getting Report" -Status "Report will be saved to the system temp directory"
            $un = $script:credentials.GetNetworkCredential().Username
            $pass = $script:credentials.GetNetworkCredential().Password
            [uri]$ReportUrl = "https://$script:server/data/report/$reportName"
            $httpResponse = Get-HTTP -Username $un -Password $pass -Url $ReportUrl

            Write-Progress -Activity "Creating Memory Stream" -Status "Reading in $httpResponse"        
            $s = [IO.File]::OpenRead($httpResponse)
            #$s = [IO.MemoryStream]([Text.Encoding]::UTF8.GetBytes($httpResponse))

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

        #If we're working off the server, clear out the temporary file
        if ($PSCmdlet.ParameterSetName -eq 'ReportUrl') {
            if ($keepTempFile) {
                Write-Verbose "Keeping $httpResponse per request"
            } else {
                Remove-Item $httpResponse
            }
        }


    }
}