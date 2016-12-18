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
