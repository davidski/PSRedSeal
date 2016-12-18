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
