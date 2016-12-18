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
