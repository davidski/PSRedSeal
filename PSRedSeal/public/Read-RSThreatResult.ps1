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
        } elseif ($null -ne $rawXml.ThreatResults.Message) {
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
